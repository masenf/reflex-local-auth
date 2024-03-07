# local-auth

Easy access to local authentication in your [Reflex](https://reflex.dev) app.

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

The basic `reflex_local_auth.User` model provides password hashing and
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
        registration_result = super().handle_registration(form_data)
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
            icon="alert_triangle",
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
import sqlmodel
import reflex as rx
import reflex_local_auth


class MyLocalAuthState(reflex_local_auth.LocalAuthState):
    @rx.cached_var
    def authenticated_user_info(self) -> UserInfo | None:
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