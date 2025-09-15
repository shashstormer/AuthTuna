import pytest
from authtuna.core.social import get_social_provider, oauth

def test_get_social_provider_valid():
    # These providers may or may not be registered depending on settings, but the function should not error
    for provider in ["google", "github"]:
        client = get_social_provider(provider)
        assert client is None or hasattr(client, 'authorize_redirect')

def test_get_social_provider_invalid():
    assert get_social_provider("notarealprovider") is None

def test_oauth_registry_is_accessible():
    # The oauth object should be present and have a registry dict
    print(oauth)
    assert hasattr(oauth, '_registry')
    assert isinstance(oauth._registry, dict)

