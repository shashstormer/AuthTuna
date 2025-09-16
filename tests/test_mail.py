from unittest.mock import patch, MagicMock

import pytest

from authtuna.helpers.mail import EmailManager


class DummySettings:
    SMTP_HOST = 'smtp.example.com'
    SMTP_PORT = 587
    SMTP_USERNAME = 'user'
    SMTP_PASSWORD = MagicMock(get_secret_value=lambda: 'pass')
    DEFAULT_SENDER_EMAIL = 'noreply@example.com'
    USE_CREDENTIALS = True
    EMAIL_TEMPLATE_DIR = '.'
    EMAIL_ENABLED = True
    VALIDATE_CERTS = True

@patch('authtuna.helpers.mail.settings', new=DummySettings)
def test_get_template_cache_and_not_found(tmp_path):
    mgr = EmailManager()
    # Write a template file
    template_path = tmp_path / 'test.html'
    template_path.write_text('Hello, {{name}}!')
    mgr.template_dir = tmp_path
    # First load (from disk)
    assert mgr._get_template('test.html') == 'Hello, {{name}}!'
    # Second load (from cache)
    assert mgr._get_template('test.html') == 'Hello, {{name}}!'
    # Not found
    assert mgr._get_template('notfound.html') == ''

@patch('authtuna.helpers.mail.settings', new=DummySettings)
def test_get_template_error(monkeypatch, tmp_path):
    mgr = EmailManager()
    mgr.template_dir = tmp_path
    # Simulate error
    monkeypatch.setattr('pathlib.Path.read_text', lambda self, encoding: (_ for _ in ()).throw(Exception('fail')))
    assert mgr._get_template('fail.html') == ''

@patch('authtuna.helpers.mail.settings', new=DummySettings)
@patch('smtplib.SMTP')
def test_send_smtp_message_success(mock_smtp):
    mgr = EmailManager()
    msg = MagicMock()
    msg.__getitem__.side_effect = lambda k: 'to@example.com' if k == 'To' else 'subject' if k == 'Subject' else ''
    mgr._send_smtp_message(msg)
    assert mock_smtp.called

@patch('authtuna.helpers.mail.settings', new=DummySettings)
@patch('smtplib.SMTP', side_effect=Exception('fail'))
def test_send_smtp_message_error(mock_smtp):
    mgr = EmailManager()
    msg = MagicMock()
    msg.__getitem__.side_effect = lambda k: 'to@example.com'
    mgr._send_smtp_message(msg)  # Should not raise

@patch('authtuna.helpers.mail.settings', new=DummySettings)
@pytest.mark.asyncio
def test_send_email_async_disabled():
    mgr = EmailManager()
    mgr.sender_email = 'noreply@example.com'
    DummySettings.EMAIL_ENABLED = False
    called = {}
    class BG:
        def add_task(self, fn):
            called['yes'] = True
    import asyncio
    asyncio.run(mgr.send_email_async('subj', 'to@example.com', 'notfound.html', {}, background_tasks=BG()))
    assert 'yes' in called
    DummySettings.EMAIL_ENABLED = True

