#!/usr/bin/env python3
"""
Database Initialization Script for QSS4

This script initializes the database schema and creates initial data.
"""

import os
import sys
from pathlib import Path

# Add the parent directory to Python path so we can import from the app
sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app, db
from models import User, FileRecord, AuditLog, DownloadToken
from core.security import security_manager
import click
from sqlalchemy import text

@click.command()
@click.option('--drop', is_flag=True, help='Drop all tables before creating')
@click.option('--create-admin', is_flag=True, help='Create default admin user')
@click.option('--admin-email', default='admin@qss4.local', help='Admin email address')
@click.option('--admin-password', help='Admin password (will prompt if not provided)')
def init_db(drop, create_admin, admin_email, admin_password):
    """Initialize QSS4 database schema and optionally create admin user"""
    
    print("🔧 Initializing QSS4 Database...")
    
    # Create Flask app
    app = create_app()
    
    with app.app_context():
        try:
            # Test database connection
            db.session.execute(text('SELECT 1'))
            print("✅ Database connection successful")
            
            if drop:
                print("⚠️  Dropping all tables...")
                if click.confirm('This will delete ALL data. Are you sure?'):
                    db.drop_all()
                    print("🗑️  All tables dropped")
                else:
                    print("❌ Operation cancelled")
                    return
            
            # Create all tables
            print("📋 Creating database schema...")
            db.create_all()
            print("✅ Database schema created successfully")
            
            # Verify tables were created
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            
            expected_tables = ['users', 'files', 'audit_logs', 'download_tokens']
            missing_tables = [table for table in expected_tables if table not in tables]
            
            if missing_tables:
                print(f"⚠️  Warning: Missing tables: {missing_tables}")
            else:
                print("✅ All expected tables created")
            
            # Create admin user if requested
            if create_admin:
                print(f"👤 Creating admin user: {admin_email}")
                
                # Check if admin already exists
                existing_admin = User.query.filter_by(email=admin_email).first()
                if existing_admin:
                    print(f"⚠️  User {admin_email} already exists")
                    if click.confirm('Update existing user to admin role?'):
                        existing_admin.role = 'admin'
                        existing_admin.is_active = True
                        db.session.commit()
                        print("✅ Existing user updated to admin")
                else:
                    # Get password
                    if not admin_password:
                        admin_password = click.prompt(
                            'Enter admin password', 
                            hide_input=True, 
                            confirmation_prompt=True
                        )
                    
                    # Validate password
                    if len(admin_password) < 8:
                        print("❌ Password must be at least 8 characters long")
                        return
                    
                    # Create admin user
                    admin_user = User(
                        email=admin_email,
                        password_hash=security_manager.hash_password(admin_password),
                        role='admin',
                        is_active=True
                    )
                    
                    db.session.add(admin_user)
                    db.session.commit()
                    
                    print(f"✅ Admin user created successfully")
                    print(f"   Email: {admin_email}")
                    print(f"   Role: admin")
            
            # Display database statistics
            print("\n📊 Database Statistics:")
            user_count = User.query.count()
            file_count = FileRecord.query.count()
            audit_count = AuditLog.query.count()
            token_count = DownloadToken.query.count()
            
            print(f"   Users: {user_count}")
            print(f"   Files: {file_count}")
            print(f"   Audit Logs: {audit_count}")
            print(f"   Download Tokens: {token_count}")
            
            # Display connection info
            print(f"\n🔗 Database URL: {app.config['SQLALCHEMY_DATABASE_URI']}")
            
            print("\n🎉 Database initialization completed successfully!")
            
            if create_admin:
                print(f"\n🔐 You can now login with:")
                print(f"   Email: {admin_email}")
                print(f"   Password: [hidden]")
                print(f"   Role: admin")
        
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            return 1
    
    return 0

@click.command()
def check_db():
    """Check database connection and schema"""
    print("🔍 Checking database connection...")
    
    app = create_app()
    
    with app.app_context():
        try:
            # Test basic connection
            result = db.session.execute(text('SELECT 1')).scalar()
            print("✅ Database connection successful")
            
            # Check tables
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            
            print(f"\n📋 Found {len(tables)} tables:")
            for table in sorted(tables):
                print(f"   • {table}")
            
            # Check for expected tables
            expected_tables = ['users', 'files', 'audit_logs', 'download_tokens']
            missing_tables = [table for table in expected_tables if table not in tables]
            
            if missing_tables:
                print(f"\n⚠️  Missing expected tables: {missing_tables}")
                print("   Run 'python scripts/init_db.py' to create them")
            else:
                print("\n✅ All expected tables found")
            
            # Count records
            print(f"\n📊 Record counts:")
            try:
                print(f"   Users: {User.query.count()}")
                print(f"   Files: {FileRecord.query.count()}")
                print(f"   Audit Logs: {AuditLog.query.count()}")
                print(f"   Download Tokens: {DownloadToken.query.count()}")
            except Exception as e:
                print(f"   Error counting records: {e}")
            
        except Exception as e:
            print(f"❌ Database check failed: {e}")
            return 1
    
    return 0

@click.command()
@click.option('--table', help='Specific table to reset (users, files, audit_logs, download_tokens)')
@click.option('--confirm', is_flag=True, help='Skip confirmation prompt')
def reset_db(table, confirm):
    """Reset database (delete all data)"""
    
    if not confirm:
        if not click.confirm('⚠️  This will DELETE ALL DATA. Are you sure?'):
            print("❌ Operation cancelled")
            return
    
    print("🗑️  Resetting database...")
    
    app = create_app()
    
    with app.app_context():
        try:
            if table:
                # Reset specific table
                table_map = {
                    'users': User,
                    'files': FileRecord,
                    'audit_logs': AuditLog,
                    'download_tokens': DownloadToken
                }
                
                if table not in table_map:
                    print(f"❌ Unknown table: {table}")
                    return 1
                
                model = table_map[table]
                deleted = model.query.delete()
                db.session.commit()
                print(f"✅ Deleted {deleted} records from {table}")
            else:
                # Reset all tables
                DownloadToken.query.delete()
                AuditLog.query.delete()
                FileRecord.query.delete()
                User.query.delete()
                db.session.commit()
                print("✅ All data deleted")
            
        except Exception as e:
            print(f"❌ Reset failed: {e}")
            db.session.rollback()
            return 1
    
    return 0

@click.group()
def cli():
    """QSS4 Database Management CLI"""
    pass

# Add commands to CLI group
cli.add_command(init_db)
cli.add_command(check_db)
cli.add_command(reset_db)

if __name__ == '__main__':
    cli()
