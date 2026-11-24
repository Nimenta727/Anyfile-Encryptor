"""Local public-fixture checks for candidate suites and I/O error boundaries."""
import errno
import hashlib
import os
from pathlib import Path
import tempfile
from unittest.mock import patch
from core import hdt

PARTS = ("test-alpha-001", "test-beta-002", "test-gamma-003")


def check():
    with tempfile.TemporaryDirectory() as tmp:
        p = Path(tmp)
        raw = hdt.KEY_MAGIC + b'\x00\x02' + hdt.SHAPE + bytes(16) + bytes(i % 251 for i in range(hdt.KEY_BYTES))
        (p/'key').write_bytes(raw+hashlib.sha256(raw).digest())
        (p/'src').write_bytes(b'abc')
        for suite in hdt.SUITES:
            out, recovered = p/f'{suite}.hdt', p/f'{suite}.plain'
            vals = iter([bytes(range(96,112)),bytes(range(32)),bytes(range(32,64)),bytes(range(64,96))])
            with patch.object(hdt,'_random_bytes',side_effect=lambda n:next(vals)):
                hdt.encrypt(p/'src',out,p/'key',PARTS,suite=suite)
            assert out.stat().st_size == (301 if suite in hdt.COMMITMENT_SUITES else 269)
            hdt.decrypt(out,recovered,p/'key',PARTS,max_memory_mib=1024)
            assert recovered.read_bytes()==b'abc'
            if suite in hdt.COMMITMENT_SUITES:
                bad = bytearray(out.read_bytes());bad[92]^=1;(p/'tampered').write_bytes(bad)
                try: hdt.decrypt(p/'tampered',p/'bad',p/'key',PARTS,max_memory_mib=1024)
                except hdt.FormatError: pass
                else: raise AssertionError('tampered commitment accepted')
                assert not (p/'bad').exists()
            print('PASS suite',suite,hashlib.sha256(out.read_bytes()).hexdigest(),flush=True)
        # Deliberately break a file fsync before publication.
        try:
            with patch.object(hdt.os,'fsync',side_effect=OSError(errno.EIO,'injected file fsync error')):
                with hdt.atomic_output(p/'pre') as f:f.write(b'fixture')
        except OSError as e: assert not isinstance(e,hdt.PublishedOutputError)
        else: raise AssertionError('expected fsync failure')
        assert not (p/'pre').exists() and not hdt.list_residuals(p)
        if os.name=='posix':
            real_sync=hdt.os.fsync
            calls=0
            def fail_directory(fd):
                nonlocal calls
                calls+=1
                if calls==2: raise OSError(errno.EIO,'injected directory fsync error')
                real_sync(fd)
            try:
                with patch.object(hdt.os,'fsync',side_effect=fail_directory):
                    with hdt.atomic_output(p/'post') as f:f.write(b'fixture')
            except hdt.PublishedOutputError:pass
            else:raise AssertionError('expected published output error')
            assert (p/'post').read_bytes()==b'fixture' and not hdt.list_residuals(p)
        real_unlink=hdt.os.unlink
        def fail_alias(path,*a,**kw):
            if Path(path).name.startswith('.mosaic-hdt-'):raise OSError(errno.EACCES,'injected alias cleanup error')
            return real_unlink(path,*a,**kw)
        try:
            with patch.object(hdt.os,'unlink',side_effect=fail_alias):
                with hdt.atomic_output(p/'alias') as f:f.write(b'fixture')
        except hdt.PublishedOutputError:pass
        else:raise AssertionError('expected published output error')
        residual=hdt.list_residuals(p);assert len(residual)==1 and os.path.samefile(p/residual[0],p/'alias')
        (p/residual[0]).unlink()
        print('PASS precommit fsync and postcommit cleanup/directory-sync injection',flush=True)

if __name__=='__main__':check()
