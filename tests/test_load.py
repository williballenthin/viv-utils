import pickle

import pytest

import viv_utils

EXECUTED = []


def mark_executed():
    EXECUTED.append(True)


class Payload:
    def __reduce__(self):
        return (mark_executed, ())


def write_pickle_viv(path):
    with open(path, "wb") as f:
        f.write(b"VIV".ljust(8, b"\x00") + pickle.dumps([Payload()], protocol=2))


def write_msgpack_viv(path):
    with open(path, "wb") as f:
        f.write(b"\xa8MSGVIV\x00\x00")


@pytest.mark.parametrize("write", [write_pickle_viv, write_msgpack_viv])
def test_getWorkspace_rejects_workspace_without_viv_extension(tmp_path, write):
    path = tmp_path / "sample.exe_"
    write(str(path))

    EXECUTED.clear()
    with pytest.raises(viv_utils.UnsupportedFormatError):
        viv_utils.getWorkspace(str(path), should_save=False)
    assert not EXECUTED


@pytest.mark.parametrize("write", [write_pickle_viv, write_msgpack_viv])
def test_getWorkspaceFromFile_rejects_workspace(tmp_path, write):
    path = tmp_path / "sample.exe_"
    write(str(path))

    EXECUTED.clear()
    with pytest.raises(viv_utils.UnsupportedFormatError):
        viv_utils.getWorkspaceFromFile(str(path), analyze=False)
    assert not EXECUTED


def test_guessInputFormat():
    from fixtures import DATA

    assert viv_utils.guessInputFormat(str(DATA / "Practical Malware Analysis Lab 01-01.dll_")) == "pe"


def copy_sample(tmp_path):
    from fixtures import DATA

    path = tmp_path / "pma.dll_"
    path.write_bytes((DATA / "Practical Malware Analysis Lab 01-01.dll_").read_bytes())
    return path


def test_getWorkspace_ignores_sibling_viv_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv(viv_utils.ALLOW_INSECURE_PICKLE_ENV, raising=False)
    path = copy_sample(tmp_path)
    write_pickle_viv(str(path) + ".viv")

    EXECUTED.clear()
    vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    assert not EXECUTED
    assert vw.getMeta("Format") == "pe"


@pytest.mark.parametrize("value", ["", "0", "false", "no"])
def test_getWorkspace_ignores_sibling_viv_when_not_opted_in(tmp_path, monkeypatch, value):
    monkeypatch.setenv(viv_utils.ALLOW_INSECURE_PICKLE_ENV, value)
    path = copy_sample(tmp_path)
    write_pickle_viv(str(path) + ".viv")

    EXECUTED.clear()
    viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    assert not EXECUTED


def test_getWorkspace_loads_sibling_viv_when_allowed(tmp_path, monkeypatch):
    path = copy_sample(tmp_path)

    monkeypatch.delenv(viv_utils.ALLOW_INSECURE_PICKLE_ENV, raising=False)
    vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    vw.setMeta("viv_utils_test_marker", True)
    vw.saveWorkspace()
    assert (tmp_path / "pma.dll_.viv").exists()

    # without opt-in, the cached workspace is ignored
    vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    assert not vw.getMeta("viv_utils_test_marker")

    # with opt-in, the cached workspace is loaded
    monkeypatch.setenv(viv_utils.ALLOW_INSECURE_PICKLE_ENV, "1")
    vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    assert vw.getMeta("viv_utils_test_marker")


def test_getWorkspace_loads_explicit_viv(tmp_path, monkeypatch):
    monkeypatch.delenv(viv_utils.ALLOW_INSECURE_PICKLE_ENV, raising=False)
    path = copy_sample(tmp_path)
    vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    vw.setMeta("viv_utils_test_marker", True)
    vw.saveWorkspace()

    vw = viv_utils.getWorkspace(str(path) + ".viv", should_save=False)
    assert vw.getMeta("viv_utils_test_marker")


@pytest.mark.parametrize(
    "load", [viv_utils.getWorkspaceFromBytes, lambda buf: viv_utils.loadWorkspaceFromBytes(viv_utils.Workspace(), buf)]
)
def test_workspace_from_bytes_requires_opt_in(tmp_path, monkeypatch, load):
    monkeypatch.delenv(viv_utils.ALLOW_INSECURE_PICKLE_ENV, raising=False)
    path = tmp_path / "evil.viv"
    write_pickle_viv(str(path))

    EXECUTED.clear()
    with pytest.raises(viv_utils.InsecurePickleNotAllowedError):
        load(path.read_bytes())
    assert not EXECUTED


def test_workspace_from_bytes_when_allowed(tmp_path, monkeypatch):
    path = copy_sample(tmp_path)
    vw = viv_utils.getWorkspace(str(path), analyze=False, should_save=False)
    vw.setMeta("viv_utils_test_marker", True)
    buf = viv_utils.saveWorkspaceToBytes(vw)

    monkeypatch.setenv(viv_utils.ALLOW_INSECURE_PICKLE_ENV, "1")
    vw = viv_utils.getWorkspaceFromBytes(buf, analyze=False)
    assert vw.getMeta("viv_utils_test_marker")
