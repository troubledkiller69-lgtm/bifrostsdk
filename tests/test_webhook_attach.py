"""
Webhook attachment + path-leak regression tests.

The dump webhook must (a) attach offsets.json to the Discord message and
(b) never embed local file paths in the payload — the message goes to a
remote server.
"""
import json
import os

import gui_bridge


def test_multipart_shapes_payload_and_file_parts(tmp_path):
    blob = json.dumps({"embeds": [{"title": "x"}]}).encode("utf-8")
    payload_file = tmp_path / "offsets.json"
    payload_file.write_bytes(b'{"classes": 3340}')

    body, content_type = gui_bridge._webhook_multipart(blob, str(payload_file))

    assert content_type.startswith("multipart/form-data; boundary=")
    text = body.decode("utf-8", "replace")
    assert 'name="payload_json"' in text
    assert 'name="files[0]"; filename="offsets.json"' in text
    assert text.endswith("--\r\n")


def test_multipart_never_leaks_local_directory(tmp_path):
    deep = tmp_path / "some" / "nested" / "dir"
    deep.mkdir(parents=True)
    payload_file = deep / "offsets.json"
    payload_file.write_bytes(b"{}")

    body, _ = gui_bridge._webhook_multipart(b"{}", str(payload_file))
    text = body.decode("utf-8", "replace")

    assert "nested" not in text
    assert "tmp" not in text
    assert "Users" not in text
    assert os.path.sep not in text.replace("\\", "")
