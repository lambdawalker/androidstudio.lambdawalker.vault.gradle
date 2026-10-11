"""Exercise AGP handoff with disposable credentials, never a user's signing key."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SDK = Path(os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", "")))
JAVA_HOME = Path(os.environ["JAVA_HOME"])
EXE = ".exe" if os.name == "nt" else ""
JAVA = str(JAVA_HOME / "bin" / ("java" + EXE))
KEYTOOL = str(JAVA_HOME / "bin" / ("keytool" + EXE))
SIGNER = SDK / "build-tools" / "37.0.0" / "lib" / "apksigner.jar"
FIXTURE = ROOT / "fixtures" / "android-signing"
APK_DIR = FIXTURE / "app" / "build" / "outputs" / "apk" / "debug"
GRADLE = [JAVA, "-cp", str(ROOT / "gradle/wrapper/gradle-wrapper.jar"), "org.gradle.wrapper.GradleWrapperMain"]
FLAGS = ["--no-daemon", "--no-configuration-cache", "--no-build-cache", "--no-scan", "--rerun-tasks"]

def run(args, success=True):
    result = subprocess.run(args, cwd=FIXTURE, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if (result.returncode == 0) != success:
        raise RuntimeError(result.stdout)
    return result.stdout

assert SIGNER.is_file(), "Install SDK build-tools;37.0.0 first."
assert not any(key.startswith("LW_VAULT_") for key in os.environ), "Fixture must not inherit real broker credentials."
with tempfile.TemporaryDirectory(prefix="vault-disposable-") as temporary:
    key = Path(temporary) / "fixture.p12"
    cert = Path(temporary) / "fixture.der"
    run([KEYTOOL, "-genkeypair", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048", "-dname", "CN=Disposable Vault Fixture", "-validity", "1", "-storetype", "PKCS12", "-keystore", str(key), "-storepass", "disposable-fixture-password"])
    run([KEYTOOL, "-exportcert", "-alias", "fixture", "-keystore", str(key), "-storepass", "disposable-fixture-password", "-file", str(cert)])
    expected = hashlib.sha256(cert.read_bytes()).hexdigest()
    run(GRADLE + [":app:assembleDebug"] + FLAGS)
    unsigned = APK_DIR / "app-debug-unsigned.apk"
    assert unsigned.is_file(), "Locked fixture must produce an unsigned APK."
    run([JAVA, "-jar", str(SIGNER), "verify", str(unsigned)], success=False)
    run(GRADLE + [":app:assembleDebug", "-PspikeKeystore=" + str(key)] + FLAGS)
    signed = APK_DIR / "app-debug.apk"
    output = run([JAVA, "-jar", str(SIGNER), "verify", "--print-certs", str(signed)])
    matches = re.findall(r"certificate SHA-256 digest: ([0-9a-f]+)", output)
    assert matches == [expected], "APK certificate differs from the disposable keystore."
    run(GRADLE + [":app:assembleDebug", "-PspikeKeystore=" + str(key), "-PspikeWrongPassword=true"] + FLAGS, success=False)
    print("PASS: locked APK unsigned; finalized signing config produces expected certificate; wrong password fails.")
