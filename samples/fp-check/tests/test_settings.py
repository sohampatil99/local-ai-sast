from unittest import mock

import settings

TEST_DB_PASSWORD = "changeme-test-only-0000"


@mock.patch("settings.connect")
def test_connect_uses_password(connect):
    settings.open_db(password=TEST_DB_PASSWORD)
    connect.assert_called_once()
