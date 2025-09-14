import pytest
from authtuna.helpers.mail import email_manager
from fastapi import BackgroundTasks
import os

class DummyBackgroundTasks:
    def __init__(self):
        self.tasks = []
    def add_task(self, func, *args, **kwargs):
        self.tasks.append((func, args, kwargs))

def test_template_loading_and_context():
    email_manager.template_cache.clear()
    template_name = "welcome.html"
    template_path = os.path.join(email_manager.template_dir, template_name)
    if not os.path.exists(template_path):
        with open(template_path, "w", encoding="utf-8") as f:
            f.write("Hello, {{{{ username }}}}!")
    html = email_manager._get_template(template_name)
    assert "{{ username }}" in html
    context = {"username": "TestUser"}
    for key, value in context.items():
        html = html.replace(f"{{{{ {key} }}}}", str(value))
    assert "TestUser" in html

def test_send_email_async(monkeypatch):
    monkeypatch.setattr(email_manager, "_send_smtp_message", lambda msg: None)
    tasks = DummyBackgroundTasks()
    import asyncio
    asyncio.run(email_manager.send_email_async(
        subject="Test Subject",
        email_to="test@example.com",
        template_name="welcome.html",
        context={"username": "TestUser"},
        background_tasks=tasks
    ))
    assert tasks.tasks
