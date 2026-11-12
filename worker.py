"""Build a SHA-pinned Unity iOS export with private Git transport."""
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import zipfile


CHUNK_SIZE = 48 * 1024 * 1024
ARCHIVE_LIMIT = 1024 * 1024 * 1024
GITHUB_KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl'
OUTPUT_FILES = (
    'app.ipa', 'app.ipa.sha256', 'build-report.json', 'input-verification.json',
    'apple-jsc/result.json', 'xcodebuild-tail.txt', 'worker.log',
)


def check(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def split_archive(archive, destination):
    length = archive.stat().st_size
    check(0 < length <= ARCHIVE_LIMIT, 'Unsupported transfer size')
    manifest = {'bytes': length, 'sha256': sha256(archive)}
    count = 0
    with archive.open('rb') as source:
        for data in iter(lambda: source.read(CHUNK_SIZE), b''):
            with (destination / f'part-{count:03d}.bin').open('xb') as output:
                output.write(data)
            count += 1
    manifest['parts'] = count
    with (destination / 'transfer.json').open('x', encoding='utf-8') as output:
        json.dump(manifest, output)


def join_archive(directory, destination, expected_sha=None):
    manifest_path = directory / 'transfer.json'
    check(manifest_path.is_file() and not manifest_path.is_symlink() and manifest_path.stat().st_size <= 4096,
          'Invalid transfer manifest')
    manifest = json.loads(manifest_path.read_bytes())
    length, count, digest = manifest['bytes'], manifest['parts'], manifest['sha256']
    check(type(length) is int and 0 < length <= ARCHIVE_LIMIT and type(count) is int and
          count == (length + CHUNK_SIZE - 1) // CHUNK_SIZE, 'Invalid chunk count')
    check(isinstance(digest, str) and re.fullmatch(r'[0-9a-f]{64}', digest) and
          (expected_sha is None or digest == expected_sha), 'Unexpected archive hash')
    names = [f'part-{number:03d}.bin' for number in range(count)]
    check({path.name for path in directory.iterdir()} - {'.git'} == {*names, 'transfer.json'},
          'Unexpected transfer files')
    observed = hashlib.sha256()
    with destination.open('xb') as output:
        for number, name in enumerate(names):
            path = directory / name
            size = min(CHUNK_SIZE, length - number * CHUNK_SIZE)
            check(path.is_file() and not path.is_symlink() and path.stat().st_size == size, 'Invalid transfer chunk')
            with path.open('rb') as source:
                for block in iter(lambda: source.read(1024 * 1024), b''):
                    output.write(block)
                    observed.update(block)
    check(observed.hexdigest() == digest, 'Transfer data hash mismatch')


def transfer_ref(transfer_id, kind):
    check(re.fullmatch(r'[0-9a-f]{32}', transfer_id) and kind in {'input', 'result'},
          'Invalid transfer identifier')
    return f'refs/heads/build-transfer/{transfer_id}-{kind}'


def command(arguments, *, cwd=None, env=None, log=None, timeout=300, required=True):
    if log is None:
        stdout = subprocess.DEVNULL
    else:
        stdout = log
    result = subprocess.run([str(value) for value in arguments], cwd=cwd, env=env, stdout=stdout,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if required:
        check(result.returncode == 0, 'Build or transfer command failed')
    return result.returncode


@contextmanager
def private_remote(directory):
    repo = os.environ['TRANSFER_REPO']
    check(re.fullmatch(r'[A-Za-z0-9-]+/[A-Za-z0-9_.-]+', repo) and
          repo.split('/')[1] not in {'.', '..'}, 'Invalid private repository')
    private_key = os.environ['TRANSFER_KEY']
    check(private_key.startswith('-----BEGIN OPENSSH PRIVATE KEY-----'), 'Missing transfer credential')
    with tempfile.TemporaryDirectory(prefix='ssh-', dir=directory) as temporary:
        key = Path(temporary) / 'identity'
        hosts = Path(temporary) / 'known_hosts'
        with key.open('x', encoding='ascii') as stream:
            stream.write(private_key.rstrip() + '\n')
        key.chmod(0o600)
        hosts.write_text(f'github.com {GITHUB_KEY}\n', encoding='ascii')
        ssh = ['ssh', '-i', str(key), '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes', '-o',
               'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={hosts}', '-o', 'HostKeyAlgorithms=ssh-ed25519']
        env = {name: value for name, value in os.environ.items() if name not in {'TRANSFER_KEY', 'TRANSFER_REPO'}}
        env.update(GIT_SSH_COMMAND=shlex.join(ssh), GIT_TERMINAL_PROMPT='0')
        yield f'git@github.com:{repo}.git', env


def receive(directory, transfer_id, digest):
    check(re.fullmatch(r'[0-9a-f]{64}', digest), 'Invalid archive hash')
    with tempfile.TemporaryDirectory(prefix='input-', dir=directory) as temporary:
        with private_remote(directory) as (url, env):
            command(['git', 'init', '-q'], cwd=temporary, env=env)
            command(['git', 'fetch', '--depth=1', '--no-tags', url, transfer_ref(transfer_id, 'input')],
                    cwd=temporary, env=env)
            command(['git', 'checkout', '-q', '--detach', 'FETCH_HEAD'], cwd=temporary, env=env)
        join_archive(Path(temporary), directory / 'input.zip', digest)


def build(directory, digest, source_commit):
    check(re.fullmatch(r'[0-9a-f]{64}', digest) and re.fullmatch(r'[0-9a-f]{40}', source_commit),
          'Invalid build provenance')
    check('TRANSFER_KEY' not in os.environ, 'Unexpected credential in build step')
    archive, exported, output = directory / 'input.zip', directory / 'extracted', directory / 'output'
    output.mkdir()
    helpers = directory / 'helpers'
    helpers.mkdir()
    check(sha256(archive) == digest, 'Incorrect input archive')
    with zipfile.ZipFile(archive) as zipped:
        for name in ('validator.py', 'builder.py', 'jsc-smoke.py'):
            info = zipped.getinfo(name)
            check(0 < info.file_size <= 1024 * 1024, 'Invalid build helper')
            (helpers / name).write_bytes(zipped.read(info))
    validator = [sys.executable, helpers / 'validator.py']
    with (output / 'worker.log').open('wb') as log:
        command([*validator, 'extract', '--archive', archive, '--target', exported, '--sha256', digest,
                 '--source-commit', source_commit, '--builder', helpers / 'builder.py',
                 '--jsc-smoke', helpers / 'jsc-smoke.py', '--report', output / 'input-verification.json'],
                log=log)
        archive.unlink()
        project = exported / 'ios-export'
        command([*validator, 'repair', '--project', project, '--report', directory / 'permissions.json'], log=log)
        command([sys.executable, helpers / 'jsc-smoke.py', '--project', project,
                 '--fixture', exported / 'qa-first-battle.json',
                 '--fade-out-fixture', exported / 'qa-actor-fade-out.json',
                 '--fade-in-fixture', exported / 'qa-actor-fade-in.json',
                 '--round-fixture', exported / 'qa-round-boundary.json',
                 '--sound-fixture', exported / 'qa-ordinary-sound.json',
                 '--output', output / 'apple-jsc', '--source-commit', source_commit], log=log)
        ipa = output / 'app.ipa'
        try:
            command([sys.executable, helpers / 'builder.py', '--project', project, '--ipa', ipa,
                     '--work-root', directory / 'build', '--report', output / 'build-report.json'],
                    log=log, timeout=2600)
            command([*validator, 'sha', '--ipa', ipa], log=log)
        finally:
            command([*validator, 'logs', '--root', directory / 'build', '--output', output / 'xcodebuild-tail.txt'],
                    log=log, required=False)


def send(directory, transfer_id):
    output = directory / 'output'
    with tempfile.TemporaryDirectory(prefix='result-', dir=directory) as temporary:
        root = Path(temporary)
        archive = root / 'result.zip'
        with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_STORED) as zipped:
            for name in OUTPUT_FILES:
                source = output / name
                if source.is_file() and not source.is_symlink():
                    zipped.write(source, name)
        repository = root / 'repository'
        repository.mkdir()
        split_archive(archive, repository)
        with private_remote(directory) as (url, env):
            command(['git', 'init', '-q'], cwd=repository, env=env)
            command(['git', 'add', '--', 'transfer.json', 'part-*.bin'], cwd=repository, env=env)
            command(['git', '-c', 'user.name=Build worker', '-c', 'user.email=build@users.noreply.github.com',
                     'commit', '-qm', 'Private build result'], cwd=repository, env=env)
            command(['git', 'push', url, 'HEAD:' + transfer_ref(transfer_id, 'result')],
                    cwd=repository, env=env, timeout=600)


def main():
    phase = sys.argv[1] if len(sys.argv) == 2 else ''
    try:
        directory = Path(os.environ['RUNNER_TEMP']) / 'unity-ios-worker'
        directory.mkdir(exist_ok=True)
        if phase == 'receive':
            receive(directory, os.environ['TRANSFER_ID'], os.environ['ARCHIVE_SHA256'])
        elif phase == 'build':
            build(directory, os.environ['ARCHIVE_SHA256'], os.environ['SOURCE_COMMIT'])
        elif phase == 'send':
            send(directory, os.environ['TRANSFER_ID'])
        else:
            raise ValueError('Unknown worker phase')
        print(f'{phase} completed')
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        # Detailed diagnostics travel with the private result.
        print(f'{phase} failed ({type(error).__name__})', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
