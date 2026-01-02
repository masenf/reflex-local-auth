# local-auth

Easy access to local authentication in your [Reflex](https://reflex.dev) app.

## Features

- **Local User Management**: Create, authenticate, and manage users with bcrypt password hashing
- **Session Management**: Secure session tokens with configurable expiration
- **HttpOnly Cookie Support**: Protect against XSS attacks with server-side authentication (NEW!)
- **ASGI Middleware**: Server-side route protection that eliminates content flash (NEW!)
- **Return URL Support**: `?next=` parameter for post-login redirects (NEW!)

## Installation

```bash
pip install reflex-local-auth
```

## Usage

```python
import reflex_local_auth
```

### Add the canned login and registration pages

If you don't want to create your own login and registration forms, add the canned pages to your app:

```python
app = rx.App()
...
app.add_page(
    reflex_local_auth.pages.login_page,
    route=reflex_local_auth.routes.LOGIN_ROUTE,
    title="Login",
)
app.add_page(
    reflex_local_auth.pages.register_page,
    route=reflex_local_auth.routes.REGISTER_ROUTE,
    title="Register",
)
```

### Create Database Tables

```console
reflex db init  # if needed
reflex db makemigrations
reflex db migrate
```

### Redirect Pages to Login

Use the `@reflex_local_auth.require_login` decorator to redirect unauthenticated users to the LOGIN_ROUTE.

```python
@rx.page()
@reflex_local_auth.require_login
def need2login(request):
    return rx.heading("Accessing this page will redirect to the login page if not authenticated.")
```

Although this _seems_ to protect the content, it is still publicly accessible
when viewing the source code for the page! This should be considered a mechanism
to redirect users to the login page, NOT a way to protect data.

### Server-Side Authentication with Middleware (Recommended)

For production applications, use the `AuthMiddleware` with the Auth API to validate
authentication on the server **before** any page content is sent to the browser. This:

1. **Eliminates content flash**: Users never see protected pages before redirect
2. **Protects against XSS**: Uses HttpOnly cookies that JavaScript cannot access
3. **Supports return URLs**: The `?next=` parameter remembers where users were going

```python
import reflex as rx
import reflex_local_auth

# Configure the middleware (optional)
reflex_local_auth.configure_middleware(
    public_routes={"/login", "/register", "/about"},  # Routes that don't require auth
    login_route="/login",
    default_authenticated_route="/dashboard",
    cookie_secure=True,  # Set to True in production with HTTPS
)

# Add middleware AND auth API to your app
app = rx.App(
    api_transformer=lambda api: reflex_local_auth.setup_auth_api(
        reflex_local_auth.AuthMiddleware(api)
    ),
)
```

### Authentication API Endpoints

The library provides REST API endpoints for authentication that set true HttpOnly
cookies (not accessible by JavaScript):

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate and set HttpOnly session cookie |
| `/api/auth/logout` | POST | Clear session cookie and invalidate session |
| `/api/auth/me` | GET | Get current authenticated user info |

**Login Request:**
```javascript
const response = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'user', password: 'pass' }),
    credentials: 'include'  // Important: include cookies
});
const data = await response.json();
// { success: true, message: "Login successful", user_id: 1, username: "user" }
```

**Check Authentication:**
```javascript
const response = await fetch('/api/auth/me', { credentials: 'include' });
const data = await response.json();
// { authenticated: true, user_id: 1, username: "user", enabled: true }
```

**Logout:**
```javascript
await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
```

**How it works:**

```
Without Middleware (flash):
  Request → Server sends HTML → Browser renders → JavaScript checks auth → Redirect
                                      ↑ FLASH

With Middleware (no flash):
  Request → Middleware checks cookie → [Valid: Serve page] or [Invalid: HTTP 302 redirect]
                                        ↑ No content sent before auth check
```

**Configuration Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `public_routes` | `{"/login", "/register", ...}` | Routes that don't require authentication |
| `public_prefixes` | `("/_next/", "/static/", ...)` | URL prefixes that don't require auth |
| `login_route` | `"/login"` | Where to redirect unauthenticated users |
| `default_authenticated_route` | `"/"` | Where to redirect authenticated users from login page |
| `cookie_secure` | `False` | Set `True` in production (requires HTTPS) |
| `enabled` | `True` | Enable/disable the middleware |

### Protect State

It is _extremely_ important to protect private data returned by State via Event
Handlers! All static page data should be considered public, the only data that
can truly be considered private at runtime must be fetched by an event handler
that checks the authenticated user and assigns the data to a State Var. After
the user logs out, the private data should be cleared and the user's tab should
be closed to destroy the session identifier.

```python
import reflex_local_auth


class ProtectedState(reflex_local_auth.LocalAuthState):
    data: str

    def on_load(self):
        if not self.is_authenticated:
            return reflex_local_auth.LoginState.redir
        self.data = f"This is truly private data for {self.authenticated_user.username}"

    def do_logout(self):
        self.data = ""
        return reflex_local_auth.LocalAuthState.do_logout


@rx.page(on_load=ProtectedState.on_load)
@reflex_local_auth.require_login
def protected_page():
    return rx.heading(ProtectedState.data)
```

## Customization

The basic `reflex_local_auth.LocalUser` model provides password hashing and
verification, and an enabled flag. Additional functionality can be added by
creating a new `UserInfo` model and creating a foreign key relationship to the
`user.id` field.

```python
import sqlmodel
import reflex as rx
import reflex_local_auth


class UserInfo(rx.Model, table=True):
    email: str
    is_admin: bool = False
    created_from_ip: str

    user_id: int = sqlmodel.Field(foreign_key="user.id")
```

To populate the extra fields, you can create a custom registration page and
state that asks for the extra info, or it can be added via other event handlers.

A custom registration state and form might look like:

```python
import reflex as rx
import reflex_local_auth
from reflex_local_auth.pages.components import input_100w, MIN_WIDTH, PADDING_TOP


class MyRegisterState(reflex_local_auth.RegistrationState):
    # This event handler must be named something besides `handle_registration`!!!
    def handle_registration_email(self, form_data):
        registration_result = self.handle_registration(form_data)
        if self.new_user_id >= 0:
            with rx.session() as session:
                session.add(
                    UserInfo(
                        email=form_data["email"],
                        created_from_ip=self.router.headers.get(
                            "x_forwarded_for",
                            self.router.session.client_ip,
                        ),
                        user_id=self.new_user_id,
                    )
                )
                session.commit()
        return registration_result


def register_error() -> rx.Component:
    """Render the registration error message."""
    return rx.cond(
        reflex_local_auth.RegistrationState.error_message != "",
        rx.callout(
            reflex_local_auth.RegistrationState.error_message,
            icon="triangle_alert",
            color_scheme="red",
            role="alert",
            width="100%",
        ),
    )


def register_form() -> rx.Component:
    """Render the registration form."""
    return rx.form(
        rx.vstack(
            rx.heading("Create an account", size="7"),
            register_error(),
            rx.text("Username"),
            input_100w("username"),
            rx.text("Email"),
            input_100w("email"),
            rx.text("Password"),
            input_100w("password", type="password"),
            rx.text("Confirm Password"),
            input_100w("confirm_password", type="password"),
            rx.button("Sign up", width="100%"),
            rx.center(
                rx.link("Login", on_click=lambda: rx.redirect(reflex_local_auth.routes.LOGIN_ROUTE)),
                width="100%",
            ),
            min_width=MIN_WIDTH,
        ),
        on_submit=MyRegisterState.handle_registration_email,
    )


def register_page() -> rx.Component:
    """Render the registration page.

    Returns:
        A reflex component.
    """

    return rx.center(
        rx.cond(
            reflex_local_auth.RegistrationState.success,
            rx.vstack(
                rx.text("Registration successful!"),
            ),
            rx.card(register_form()),
        ),
        padding_top=PADDING_TOP,
    )
```


Finally you can create a substate of `reflex_local_auth.LocalAuthState` which fetches
the associated `UserInfo` record and makes it available to your app.

```python
from typing import Optional

import sqlmodel
import reflex as rx
import reflex_local_auth


class MyLocalAuthState(reflex_local_auth.LocalAuthState):
    @rx.var(cache=True)
    def authenticated_user_info(self) -> Optional[UserInfo]:
        if self.authenticated_user.id < 0:
            return
        with rx.session() as session:
            return session.exec(
                sqlmodel.select(UserInfo).where(
                    UserInfo.user_id == self.authenticated_user.id
                ),
            ).one_or_none()


@rx.page()
@reflex_local_auth.require_login
def user_info():
    return rx.vstack(
        rx.text(f"Username: {MyLocalAuthState.authenticated_user.username}"),
        rx.cond(
            MyLocalAuthState.authenticated_user_info,
            rx.fragment(
                rx.text(f"Email: {MyLocalAuthState.authenticated_user_info.email}"),
                rx.text(f"Account Created From: {MyLocalAuthState.authenticated_user_info.created_from_ip}"),
            ),
        ),
    )
```

## Migrating from 0.0.x to 0.1.x

The `User` model has been renamed to `LocalUser` and the `AuthSession` model has
been renamed to `LocalAuthSession`. If your app was using reflex-local-auth 0.0.x,
then you will need to make manual changes to migration script to copy existing user
data into the new tables _after_ running `reflex db makemigrations`.

See [`local_auth_demo/alembic/version/cb01e050df85_.py`](local_auth_demo/alembic/version/cb01e050df85_.py) for an example migration script.

Importantly, your `upgrade` function should include the following lines, after creating
the new tables and before dropping the old tables:

```python
    op.execute("INSERT INTO localuser SELECT * FROM user;")
    op.execute("INSERT INTO localauthsession SELECT * FROM authsession;")
```

## Security Best Practices

### Authentication Architecture

The library uses a dual-storage pattern for optimal security and compatibility:

| Storage | Purpose | XSS Protection |
|---------|---------|----------------|
| localStorage | Reflex WebSocket auth & state hydration | Vulnerable |
| HttpOnly Cookie | Server-side middleware validation | Protected |

**Why dual storage?**
- Reflex requires localStorage for its internal WebSocket authentication
- HttpOnly cookies cannot be read by JavaScript (XSS protection)
- The middleware validates the HttpOnly cookie before serving pages
- Even if localStorage is compromised via XSS, protected routes remain secure

### Recommended Production Setup

```python
import reflex as rx
import reflex_local_auth

# 1. Configure middleware for production
reflex_local_auth.configure_middleware(
    cookie_secure=True,  # Requires HTTPS
    public_routes={"/login", "/register"},
)

# 2. Add BOTH middleware AND auth API to app
app = rx.App(
    api_transformer=lambda api: reflex_local_auth.setup_auth_api(
        reflex_local_auth.AuthMiddleware(api)
    ),
)

# 3. Still use @require_login as defense-in-depth
@rx.page()
@reflex_local_auth.require_login
def protected_page():
    return rx.text("Protected content")
```

### Using the Auth API from Custom Login Forms

For full security, your login flow should:
1. Call the API to set the HttpOnly cookie (middleware protection)
2. Set localStorage token for Reflex state compatibility

**Complete Login Example:**

```python
import reflex as rx
import reflex_local_auth

class MyLoginState(reflex_local_auth.LocalAuthState):
    error_message: str = ""
    is_loading: bool = False

    @rx.event
    def handle_submit(self, form_data: dict):
        """Handle login form submission."""
        self.is_loading = True
        self.error_message = ""

        # The login is handled in two parts:
        # 1. JavaScript calls /api/auth/login to set HttpOnly cookie
        # 2. On success, we call _login() to set localStorage
        yield rx.call_script(
            f"""
            fetch('/api/auth/login', {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                credentials: 'include',
                body: JSON.stringify({{
                    username: '{form_data.get("username", "")}',
                    password: '{form_data.get("password", "")}'
                }})
            }})
            .then(r => r.json())
            .then(data => {{
                if (data.success) {{
                    // Dispatch event to complete login in Reflex state
                    window.dispatchEvent(new CustomEvent('login_success',
                        {{detail: {{user_id: data.user_id}}}}));
                }} else {{
                    window.dispatchEvent(new CustomEvent('login_error',
                        {{detail: {{message: data.message}}}}));
                }}
            }})
            """
        )

    @rx.event
    def on_login_success(self, user_id: int):
        """Complete login by setting localStorage."""
        self._login(user_id)
        self.is_loading = False
        return rx.redirect("/dashboard")

    @rx.event
    def on_login_error(self, message: str):
        """Handle login error."""
        self.error_message = message
        self.is_loading = False
```

**Complete Logout Example:**

```python
    @rx.event
    def handle_logout(self):
        """Logout from both HttpOnly cookie and localStorage."""
        # 1. Clear localStorage (Reflex state)
        self.do_logout()

        # 2. Clear HttpOnly cookie via API
        yield rx.call_script(
            """
            fetch('/api/auth/logout', {
                method: 'POST',
                credentials: 'include'
            }).then(() => {
                window.location.href = '/login';
            });
            """
        )
```

### Open Redirect Prevention

The `?next=` parameter is validated to prevent open redirect attacks:
- Only relative URLs are allowed (must start with `/`)
- Protocol injection is blocked (`://`)
- Path traversal is blocked (`..`)

**Important:** When handling the `next` parameter after login, always validate it:

```python
import reflex_local_auth

class LoginState(rx.State):
    def handle_login_success(self):
        # Get next parameter from URL
        next_url = self.router.page.params.get("next", "/dashboard")

        # ALWAYS validate before redirecting
        if reflex_local_auth.is_safe_redirect_url(next_url):
            return rx.redirect(next_url)
        else:
            return rx.redirect("/dashboard")  # Fallback to safe default
```

### Rate Limiting

Login attempts are rate limited to prevent brute force attacks:
- Maximum 5 attempts per 5-minute window
- 15-minute lockout after exceeding limit
- Rate limit clears on successful login

Rate-limited requests receive HTTP 429 with a `Retry-After` header.

**Note:** Rate limiting uses in-memory storage, which means:
- Limits reset on server restart
- In multi-worker deployments, each worker has separate limits
- For production with high-security requirements, consider adding Redis-backed rate limiting

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

MIT License