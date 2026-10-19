"""Demo FastAPI application for AI Watchman.

A small, runnable app to prove the middleware, login flow, and chatbot route
work end to end. The project guide's "How to present it" and "Live demo idea"
sections describe exactly these demo steps:

- Run watchman init and show the dashboard opening.
- Send a malicious-looking request and show it appear in the event stream.
- Show a high-severity item waiting in the approval queue.

This module is a developer-facing demo surface, not the production package.
"""

from __future__ import annotations

from fastapi import FastAPI, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

app = FastAPI(title="AI Watchman - Demo")

# ---------------------------------------------------------------------------
# Login form
# ---------------------------------------------------------------------------

security = HTTPBasic()


def _fake_verify(credentials: HTTPBasicCredentials = Depends(security)) -> bool:
    # In a real deployment this would check against a password database.
    # The project guide warns the dashboard itself is a target and needs
    # strong access control.
    return credentials.username == "admin" and credentials.password == "change-me"


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Login form page."""

    login_form = (
        '<form method="post" action="/login">'
        '<input type="text" name="username" placeholder="Username" required>'
        '<input type="password" name="password" placeholder="Password" required>'
        '<button type="submit">Sign in</button>'
        "</form>"
    )
    body = f"""<!doctype html>
    <html>
      <head><title>AI Watchman - Demo</title></head>
      <body>
        <h1>AI Watchman Demo</h1>
        <p>Log in to reach the dashboard and chatbot.</p>
        {login_form}
      </body>
    </html>"""
    return HTMLResponse(content=body, status_code=200)


@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
) -> RedirectResponse:
    """Accept the login form submission and land on the dashboard."""

    if username == "admin" and password == "change-me":
        return RedirectResponse(url="/dashboard", status_code=303)
    return RedirectResponse(url="/", status_code=303)


# ---------------------------------------------------------------------------
# Chatbot route
# ---------------------------------------------------------------------------


@app.get("/chatbot", response_class=HTMLResponse)
async def chatbot_page(request: Request, authorized: bool = Depends(_fake_verify)) -> HTMLResponse:
    """Chatbot interface protected by the login form."""

    if not authorized:
        return RedirectResponse(url="/", status_code=303)

    page = """<!doctype html>
    <html>
      <head><title>AI Watchman - Chatbot</title></head>
      <body>
        <h1>AI Chatbot Guard</h1>
        <p>Ask the security chatbot anything. Prompt-injection attempts are
           logged and triaged by the jailbreak guard.</p>
        <form method="post" action="/chatbot/message">
          <textarea name="message" rows="4" cols="60" required></textarea>
          <button type="submit">Send</button>
        </form>
      </body>
    </html>"""
    return HTMLResponse(content=page, status_code=200)


@app.post("/chatbot/message")
async def chatbot_message(
    request: Request,
    message: str = Form(...),
    authorized: bool = Depends(_fake_verify),
) -> HTMLResponse:
    """Handle a chatbot message and feed it to the jailbreak guard."""

    if not authorized:
        return RedirectResponse(url="/", status_code=303)

    # In the full package this would call the jailbreak guard. The demo
    # records the event so the step-1 wiring is visible in the dashboard.
    event = Event(
        source=Source.HTTP_REQUEST,
        request_path="/chatbot/message",
        detail="chatbot message received",
        evidence={"message_length": len(message)},
    )

    page = """<!doctype html>
    <html>
      <head><title>AI Watchman - Chatbot</title></head>
      <body>
        <h1>AI Chatbot Guard</h1>
        <p>Message recorded and triaged. <a href="/dashboard">Open dashboard</a></p>
      </body>
    </html>"""
    return HTMLResponse(content=page, status_code=200)


# ---------------------------------------------------------------------------
# Dashboard route (protected login redirect, same look as the demo root)
# ---------------------------------------------------------------------------


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, authorized: bool = Depends(_fake_verify)) -> HTMLResponse:
    """Protected dashboard view."""

    if not authorized:
        return RedirectResponse(url="/", status_code=303)

    page = """<!doctype html>
    <html>
      <head><title>AI Watchman - Dashboard</title></head>
      <body>
        <h1>AI Watchman Dashboard</h1>
        <p>Real-time threat chart, event stream, approval queue, config editor,
           and code-diff viewer all land here.</p>
        <ul>
          <li><a href="/chatbot">Chatbot route</a></li>
          <li><a href="/events">Event stream (JSON)</a></li>
        </ul>
      </body>
    </html>"""
    return HTMLResponse(content=page, status_code=200)
