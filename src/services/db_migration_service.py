import os
import json
from datetime import datetime
from urllib.parse import quote
from src.utils.config_manager import BASE_DIR, MYSQL_CONFIG

SQLITE_PATH = os.path.join(BASE_DIR, 'data', 'phishing.db')
MIGRATION_FLAG_FILE = os.path.join(BASE_DIR, 'data', 'migration_status.json')


def get_migration_status():
    if os.path.exists(MIGRATION_FLAG_FILE):
        try:
            with open(MIGRATION_FLAG_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {
        'last_migration': None,
        'source_db': None,
        'target_db': None,
        'migrated_tables': []
    }


def save_migration_status(status):
    os.makedirs(os.path.dirname(MIGRATION_FLAG_FILE), exist_ok=True)
    with open(MIGRATION_FLAG_FILE, 'w', encoding='utf-8') as f:
        json.dump(status, f, indent=2, ensure_ascii=False)


def migrate_data(app, source_uri, target_uri):
    from sqlalchemy import create_engine, MetaData, Table
    from sqlalchemy.orm import sessionmaker
    from src.models.db import db, MailServerConfig, LLMConfig, EmailRecord, \
        AnalysisResult, ReplyTemplate, ReplyRecord, User, PasswordResetToken, SecurityAdviceConfig
    
    source_engine = create_engine(source_uri)
    target_engine = create_engine(target_uri)
    
    with app.app_context():
        db.metadata.create_all(target_engine)
    
    SourceSession = sessionmaker(bind=source_engine)
    TargetSession = sessionmaker(bind=target_engine)
    
    source_session = SourceSession()
    target_session = TargetSession()
    
    migrated_tables = []
    models = [
        MailServerConfig,
        LLMConfig,
        EmailRecord,
        AnalysisResult,
        ReplyTemplate,
        ReplyRecord,
        User,
        PasswordResetToken,
        SecurityAdviceConfig
    ]
    
    try:
        for model in models:
            try:
                records = source_session.query(model).all()
                if not records:
                    continue
                
                for record in records:
                    existing = target_session.query(model).get(record.id)
                    if not existing:
                        target_session.add(record)
                
                target_session.commit()
                migrated_tables.append(model.__tablename__)
            except Exception as e:
                target_session.rollback()
                print(f"迁移表 {model.__tablename__} 失败: {str(e)}")
                continue
        
        save_migration_status({
            'last_migration': datetime.now().isoformat(),
            'source_db': source_uri,
            'target_db': target_uri,
            'migrated_tables': migrated_tables
        })
        
        return {
            'success': True,
            'message': f'数据迁移成功，共迁移 {len(migrated_tables)} 个表',
            'migrated_tables': migrated_tables
        }
    finally:
        source_session.close()
        target_session.close()


def check_and_migrate(app):
    if not os.path.exists(SQLITE_PATH):
        print("SQLite数据库不存在，跳过数据迁移")
        return None
    
    status = get_migration_status()
    if status.get('last_migration'):
        print("数据已迁移过，跳过迁移")
        return None
    
    source_uri = f"sqlite:///{SQLITE_PATH}"
    host = MYSQL_CONFIG["host"]
    port = MYSQL_CONFIG["port"]
    username = MYSQL_CONFIG["username"]
    password = quote(MYSQL_CONFIG["password"], safe='')
    db_name = MYSQL_CONFIG["database_name"]
    charset = MYSQL_CONFIG["charset"]
    target_uri = f"mysql+pymysql://{username}:{password}@{host}:{port}/{db_name}?charset={charset}"
    
    try:
        return migrate_data(app, source_uri, target_uri)
    except Exception as e:
        return {
            'success': False,
            'message': f'数据迁移失败: {str(e)}',
            'migrated_tables': []
        }


def auto_migrate_columns(app):
    from sqlalchemy import inspect, text
    from src.models.db import db, MailServerConfig, LLMConfig, EmailRecord, \
        AnalysisResult, ReplyTemplate, ReplyRecord, User, PasswordResetToken, \
        SecurityAdviceConfig, ThreatIntelConfig, ThreatIntelRecord, AuditLog, \
        ChatConversation, ChatMessage, VersionInfo, PipelineConfig, \
        FoxmailConfig, AnalysisCorrection, EmailSignature
    
    models = [
        MailServerConfig,
        LLMConfig,
        EmailRecord,
        AnalysisResult,
        ReplyTemplate,
        ReplyRecord,
        User,
        PasswordResetToken,
        SecurityAdviceConfig,
        ThreatIntelConfig,
        ThreatIntelRecord,
        AuditLog,
        ChatConversation,
        ChatMessage,
        VersionInfo,
        PipelineConfig,
        FoxmailConfig,
        AnalysisCorrection,
        EmailSignature
    ]
    
    added_columns = []
    
    with app.app_context():
        inspector = inspect(db.engine)
        
        for model in models:
            table_name = model.__tablename__
            try:
                existing_columns = {col['name'] for col in inspector.get_columns(table_name)}
            except Exception:
                continue
            
            for column in model.__table__.columns:
                if column.name not in existing_columns:
                    try:
                        col_type = column.type.compile(dialect=db.engine.dialect)
                        alter_sql = f"ALTER TABLE {table_name} ADD COLUMN {column.name} {col_type}"
                        
                        if column.nullable is False and column.default is None and not column.primary_key:
                            try:
                                py_type = getattr(column.type, 'python_type', None)
                                if py_type == str:
                                    alter_sql += " DEFAULT ''"
                                elif py_type == int:
                                    alter_sql += " DEFAULT 0"
                            except Exception:
                                pass
                        
                        db.session.execute(text(alter_sql))
                        db.session.commit()
                        added_columns.append(f"{table_name}.{column.name}")
                        print(f"添加列: {table_name}.{column.name}")
                    except Exception as e:
                        db.session.rollback()
                        print(f"添加列失败 {table_name}.{column.name}: {str(e)}")
    
    if added_columns:
        print(f"数据库迁移完成，共添加 {len(added_columns)} 个新列: {', '.join(added_columns)}")
    return added_columns


def auto_migrate_column_types(app):
    """升级 TEXT 列为 MEDIUMTEXT/LONGTEXT，避免大邮件内容超长（Data too long）"""
    from sqlalchemy import inspect, text
    from src.models.db import db

    # 需要从 TEXT 升级的列：表名 -> {列名: 目标类型}
    upgrades = {
        'email_record': {'body': 'MEDIUMTEXT', 'raw_content': 'LONGTEXT'},
        'analysis_result': {'analysis_report': 'MEDIUMTEXT', 'indicators': 'MEDIUMTEXT'},
        'reply_record': {'body': 'MEDIUMTEXT', 'raw_content': 'LONGTEXT'},
    }

    upgraded = []
    with app.app_context():
        inspector = inspect(db.engine)
        for table_name, cols in upgrades.items():
            try:
                existing = inspector.get_columns(table_name)
            except Exception:
                continue
            current_types = {c['name']: str(c['type']).upper() for c in existing}
            for col_name, target in cols.items():
                if current_types.get(col_name) == 'TEXT':
                    try:
                        db.session.execute(text(f"ALTER TABLE {table_name} MODIFY COLUMN {col_name} {target}"))
                        db.session.commit()
                        upgraded.append(f"{table_name}.{col_name}")
                        print(f"升级列类型: {table_name}.{col_name} TEXT -> {target}")
                    except Exception as e:
                        db.session.rollback()
                        print(f"升级列类型失败 {table_name}.{col_name}: {e}")

    if upgraded:
        print(f"列类型迁移完成，共升级 {len(upgraded)} 个列: {', '.join(upgraded)}")
    return upgraded