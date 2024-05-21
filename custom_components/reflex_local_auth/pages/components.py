import reflex as rx

PADDING_TOP = "10vh"
MIN_WIDTH = "50vw"


def input_100w(name, **props) -> rx.Component:
    """Render a 100% width input.

    Returns:
        A reflex component.
    """
    return rx.input(
        placeholder=name.replace("_", " ").title(),
        id=name,
        name=name,
        width="100%",
        **props,
    )
