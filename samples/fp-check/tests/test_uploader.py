from unittest import mock

import uploader

FAKE_ACCESS_KEY = "AKIA0000000000000000"


@mock.patch("uploader.boto3.client")
def test_upload_uses_configured_bucket(client):
    uploader.upload(b"data", key_id=FAKE_ACCESS_KEY)
    client.return_value.put_object.assert_called_once()
