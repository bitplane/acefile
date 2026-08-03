#!/usr/bin/env python3

import glob
import io
import os
import random
import re
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)) + '/..')
import acefile



def _metadict_from_path(path):
    """
    >>> _metadict_from_path("winappdbg-winappdbg_v1.6.ace")
    {}
    >>> _metadict_from_path("winappdbg-winappdbg_v1.6_password_pw=infected.ace")
    {'pw': 'infected'}
    >>> _metadict_from_path("foo_foo=oof-bar=baz+qux=quux.ace")
    {'foo': 'oof', 'bar': 'baz', 'qux': 'quux'}
    """
    metadict = {}
    for m in re.finditer(r'([a-zA-Z0-9]+)=([a-zA-Z0-9]+)', path):
        metadict[m.group(1)] = m.group(2)
    return metadict



def pytest_generate_tests(metafunc):
    if "archive_path" not in metafunc.fixturenames:
        return
    archives = []
    here = os.path.dirname(os.path.abspath(__file__))
    subdirs = ['acefile-testdata']
    if not metafunc.config.getoption("fast"):
        subdirs.append('acefile-testdata-private')
    for subdir in subdirs:
        path = os.path.realpath(f'{here}/../../{subdir}')
        if os.path.exists(path):
            archives += glob.glob(f'{path}/**/*.ace')
            archives += glob.glob(f'{path}/**/*.exe')
    metafunc.parametrize("archive_path", archives)



def test_archive_test(archive_path):
    metadict = _metadict_from_path(archive_path)
    pwd = metadict.get('pw', None)
    with acefile.open(archive_path) as f:
        for member in f:
            if member.is_dir():
                continue
            assert f.test(member, pwd=pwd)


def test_writer_roundtrip(tmp_path):
    tree = tmp_path / 'tree'
    tree.mkdir()
    (tree / 'empty').mkdir()
    (tree / 'café.txt').write_bytes(b'hello')
    (tree / 'sub').mkdir()
    (tree / 'sub' / 'data.bin').write_bytes(bytes(range(256)))
    archive_path = tmp_path / 'test.ace'

    with acefile.open(archive_path, 'w') as archive:
        archive.write(tree, arcname='tree')

    with acefile.open(str(archive_path)) as archive:
        assert archive.getnames() == [
                'tree',
                os.path.join('tree', 'empty'),
                os.path.join('tree', 'sub'),
                os.path.join('tree', 'café.txt'),
                os.path.join('tree', 'sub', 'data.bin')]
        assert archive.read(os.path.join('tree', 'café.txt')) == b'hello'
        assert archive.read(os.path.join('tree', 'sub', 'data.bin')) == \
                bytes(range(256))
        assert archive.testall() == None


def test_bit_writer_roundtrip():
    values = [(1, 1), (2, 2), (0x1234, 16), (0, 3), (0x7FFFFFFF, 31)]
    output = io.BytesIO()
    writer = acefile.BitWriter(output)
    for value, bits in values:
        writer.write_bits(value, bits)
    writer.finish()
    output.seek(0)
    reader = acefile.BitStream(output)
    assert [reader.read_bits(bits) for _, bits in values] == \
            [value for value, _ in values]


def test_writer_compresses_and_falls_back_per_member(tmp_path):
    rng = random.Random(1)
    incompressible = bytes(rng.randrange(256) for _ in range(10000))
    with acefile.open(tmp_path / 'test.ace', 'w') as archive:
        archive.writestr('compressed', b'abcd' * 1000)
        archive.writestr('tiny', b'hello')
        archive.writestr('incompressible', incompressible)

    with acefile.open(tmp_path / 'test.ace') as archive:
        compressed = archive.getmember('compressed')
        assert compressed.comptype == acefile.COMP_LZ77
        assert compressed.compqual == acefile.QUAL_NORMAL
        assert compressed.dicsize == 1 << 20
        assert compressed.packsize < compressed.size
        assert archive.read(compressed) == b'abcd' * 1000
        assert archive.getmember('tiny').comptype == acefile.COMP_STORED
        stored = archive.getmember('incompressible')
        assert stored.comptype == acefile.COMP_STORED
        assert stored.packsize == stored.size
        assert archive.read(stored) == incompressible


def test_lz77_writer_multiple_blocks():
    rng = random.Random(2)
    data = bytes(rng.randrange(256) for _ in range(40000))
    compressed = io.BytesIO()
    acefile.LZ77Writer.write(compressed, data)
    compressed.seek(0)
    decompressor = acefile.ACE()
    assert b''.join(decompressor.decompress_lz77(
            compressed, len(data), 1 << 20)) == data


@pytest.mark.parametrize('gap, repeated, expected', [
        (253, b'abc', (268, 255, 1)),
        (300, b'abc', (269, 302, 0)),
        (9000, b'abcd', (274, 9003, 0)),
])
def test_lz77_writer_distance_thresholds(gap, repeated, expected):
    rng = random.Random(gap)
    middle = bytes(rng.randrange(256) for _ in range(gap))
    assert list(acefile.LZ77Writer._tokens(
            repeated + middle + repeated))[-1] == expected


def test_writer_explicit_store(tmp_path):
    with acefile.open(tmp_path / 'test.ace', 'w',
                      compression=acefile.COMP_STORED) as archive:
        archive.writestr('repeated', b'abcd' * 1000)
    with acefile.open(tmp_path / 'test.ace') as archive:
        member = archive.getmember(0)
        assert member.comptype == acefile.COMP_STORED
        assert member.packsize == member.size


def test_writer_rejects_duplicate_names_without_partial_member(tmp_path):
    archive_path = tmp_path / 'test.ace'
    with acefile.open(archive_path, 'w') as archive:
        archive.writestr('README', b'first')
        with pytest.raises(ValueError, match='duplicate archive name'):
            archive.writestr('readme', b'second')

    with acefile.open(str(archive_path)) as archive:
        assert archive.getnames() == ['README']
        assert archive.read(0) == b'first'


def test_writer_rejects_symlinks(tmp_path):
    target = tmp_path / 'target'
    target.write_bytes(b'target')
    link = tmp_path / 'link'
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip('symbolic links unavailable')
    archive_path = tmp_path / 'test.ace'
    with acefile.open(archive_path, 'w') as archive:
        archive.writestr('first', b'first')
        with pytest.raises(ValueError, match='symbolic links'):
            archive.write(link)
        archive.writestr('last', b'last')
    with acefile.open(archive_path) as archive:
        assert archive.getnames() == ['first', 'last']


def test_writer_validates_arguments(tmp_path):
    with acefile.open(tmp_path / 'test.ace', 'w') as archive:
        with pytest.raises(TypeError, match='bytes-like'):
            archive.writestr('text', 'not bytes')
        with pytest.raises(ValueError, match="contains '..'"):
            archive.writestr('../escape', b'data')
        with pytest.raises(ValueError, match='reserved character'):
            archive.writestr('drive:c', b'data')
        with pytest.raises(ValueError, match='archive to itself'):
            archive.write(tmp_path / 'test.ace')
    with pytest.raises(NotImplementedError, match='compression method'):
        acefile.open(tmp_path / 'compressed.ace', 'w',
                     compression=acefile.COMP_BLOCKED)


def test_writer_file64_header(tmp_path):
    with acefile.open(tmp_path / 'test.ace', 'w') as archive:
        header = archive._file_header('large.bin', 1 << 32, 0,
                acefile.Header.ATTR_ARCHIVE, 0)
    _, size = struct.unpack('<HH', header[:4])
    htype, flags, packsize, origsize = struct.unpack('<BHQQ', header[4:23])
    assert size == len(header) - 4
    assert htype == acefile.Header.TYPE_FILE64
    assert flags & acefile.Header.FLAG_64BIT
    assert packsize == origsize == 1 << 32


def test_writer_cli(tmp_path, monkeypatch):
    tree = tmp_path / 'tree'
    tree.mkdir()
    monkeypatch.chdir(tmp_path)
    (tree / 'input.txt').write_bytes(b'hello' * 1000)
    (tree / 'output.ace').write_bytes(b'old archive')
    monkeypatch.setattr(sys, 'argv',
            ['acefile-ace', 'tree/output.ace', 'tree'])
    with pytest.raises(SystemExit) as exc:
        acefile.ace()
    assert exc.value.code == 0
    with acefile.open('tree/output.ace') as archive:
        assert archive.getnames() == ['tree', os.path.join('tree', 'input.txt')]
        assert archive.getmember(1).comptype == acefile.COMP_LZ77
        assert archive.read(1) == b'hello' * 1000
    before = (tree / 'output.ace').read_bytes()
    monkeypatch.setattr(sys, 'argv',
            ['acefile-ace', 'tree/output.ace', 'missing'])
    with pytest.raises(SystemExit) as exc:
        acefile.ace()
    assert exc.value.code == 1
    assert (tree / 'output.ace').read_bytes() == before

    monkeypatch.setattr(sys, 'argv',
            ['acefile-ace', '--store', 'stored.ace', 'tree/input.txt'])
    with pytest.raises(SystemExit) as exc:
        acefile.ace()
    assert exc.value.code == 0
    with acefile.open('stored.ace') as archive:
        assert archive.getmember(0).comptype == acefile.COMP_STORED



def doctst():
    import doctest
    fails, tests = doctest.testmod(optionflags=doctest.IGNORE_EXCEPTION_DETAIL)
    sys.exit(min(1, fails))



if __name__ == '__main__':
    if '--doctest' in sys.argv:
        doctst()
    raise NotImplementedError("main")
