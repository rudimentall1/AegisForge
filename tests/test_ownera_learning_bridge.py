import sqlite3
from shared import ownera_learning_bridge as bridge


def _db(path):
    db = sqlite3.connect(path)
    db.executescript('''
    CREATE TABLE experiences(project TEXT,agent TEXT,task_type TEXT,task_summary TEXT,
      task_tags_json TEXT,status TEXT,acceptance_status TEXT,lessons TEXT,artifact_sha256 TEXT,created_at TEXT);
    CREATE TABLE skills(name TEXT,version TEXT,content TEXT,content_sha256 TEXT,verifier TEXT,status TEXT,validated_at TEXT);
    INSERT INTO experiences VALUES('OWNERA','ownera-seo-auditor','technical-seo','Read-only SEO audit',
      '["seo","technical-audit"]','COMPLETED','ACCEPTED','Check actual crawl coverage','abc','2026-11-02');
    INSERT INTO experiences VALUES('AgentFarm','developer','agent-farm:developer','Build agent integration',
      '["agent-farm","developer"]','completed','UNKNOWN','Run independent tests','def','2026-11-01');
    INSERT INTO skills VALUES('source-integrity','1.0','Verify source hash','123','ci','VALIDATED','2026-11-02');
    ''')
    db.commit(); db.close()


def test_bridge_retrieves_relevant_experience_and_validated_skills(tmp_path, monkeypatch):
    path = tmp_path / 'learning.sqlite3'; _db(path)
    monkeypatch.setattr(bridge, 'DB_PATH', path)
    context = bridge.retrieve_context('security_checker')
    assert 'Read-only SEO audit' not in context
    assert 'source-integrity@1.0' in context
    developer = bridge.retrieve_context('developer')
    assert 'Build agent integration' in developer


def test_bridge_returns_empty_for_missing_database(tmp_path, monkeypatch):
    monkeypatch.setattr(bridge, 'DB_PATH', tmp_path / 'missing.sqlite3')
    assert bridge.retrieve_context('researcher') == ''
