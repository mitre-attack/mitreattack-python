from pathlib import Path

from loguru import logger

from mitreattack.attackToJava import attackToJava

# tmp_path is a built-in pytest tixture
# https://docs.pytest.org/en/7.1.x/how-to/tmp_path.html

def check_java_files_exist(output_dir: Path):
    """Check that all expected excel files exist"""

    assert (output_dir / "src").exists()
    assert (output_dir / "target").exists()
    assert (output_dir / "src" / "main" / "java" / "org" / "mitre" / "attack" / "MitreTTP.java").exists()
    assert (output_dir / "target" / "attack-1.0-SNAPSHOT.jar").exists()

def test_latest(tmp_path: Path, stix_file_enterprise_latest: str):
    """Test most recent enterprise to excel spreadsheet functionality"""
    logger.debug(f"{tmp_path=}")

    #We need all domain stix files, so instead of enterprise file, get the path to the directory
    stix_file_path = Path(stix_file_enterprise_latest).parent

    attackToJava.export(output_dir=str(tmp_path),  stix_path=stix_file_path, package_name="org.mitre.attack", verbose_class=True)

    check_java_files_exist(output_dir=tmp_path)


