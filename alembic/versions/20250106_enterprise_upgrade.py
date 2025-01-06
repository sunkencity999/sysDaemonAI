"""enterprise upgrade

Revision ID: 20250106_01
Revises: previous_revision
Create Date: 2025-01-06 10:33:39.000000

"""
from alembic import op
import sqlalchemy as sa
from datetime import datetime

# revision identifiers, used by Alembic.
revision = '20250106_01'
down_revision = 'previous_revision'  # Update this to your previous revision
branch_labels = None
depends_on = None

def upgrade():
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=False),
        sa.Column('password_hash', sa.LargeBinary(), nullable=False),
        sa.Column('role', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('last_login', sa.DateTime()),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username')
    )
    
    # Create sessions table
    op.create_table(
        'sessions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('token', sa.String(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('is_active', sa.Boolean(), default=True),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'])
    )
    
    # Create access_logs table
    op.create_table(
        'access_logs',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('resource', sa.String(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('status', sa.String(), nullable=False),
        sa.Column('ip_address', sa.String()),
        sa.Column('user_agent', sa.String()),
        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'])
    )
    
    # Create roles table
    op.create_table(
        'roles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('permissions', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    # Create user_roles table
    op.create_table(
        'user_roles',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('role_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id']),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    
    # Insert default roles
    op.execute("""
        INSERT INTO roles (name, permissions, created_at)
        VALUES 
            ('admin', '{"*": ["read", "write", "delete"]}', :timestamp),
            ('analyst', '{"network": ["read", "write"], "system": ["read"]}', :timestamp),
            ('viewer', '{"network": ["read"], "system": ["read"]}', :timestamp)
    """, {'timestamp': datetime.now()})
    
    # Add enterprise columns to existing tables
    op.add_column('threats', sa.Column('severity_score', sa.Float()))
    op.add_column('threats', sa.Column('confidence_score', sa.Float()))
    op.add_column('threats', sa.Column('mitigation_status', sa.String()))
    op.add_column('threats', sa.Column('assigned_to', sa.Integer(), sa.ForeignKeyConstraint(['assigned_to'], ['users.id'])))
    
    op.add_column('alerts', sa.Column('escalation_level', sa.Integer()))
    op.add_column('alerts', sa.Column('assigned_to', sa.Integer(), sa.ForeignKeyConstraint(['assigned_to'], ['users.id'])))
    op.add_column('alerts', sa.Column('resolution_time', sa.Integer()))
    
    # Create indices for performance
    op.create_index('idx_threats_severity', 'threats', ['severity_score'])
    op.create_index('idx_alerts_escalation', 'alerts', ['escalation_level'])
    op.create_index('idx_access_logs_timestamp', 'access_logs', ['timestamp'])
    op.create_index('idx_sessions_token', 'sessions', ['token'])

def downgrade():
    # Remove indices
    op.drop_index('idx_threats_severity')
    op.drop_index('idx_alerts_escalation')
    op.drop_index('idx_access_logs_timestamp')
    op.drop_index('idx_sessions_token')
    
    # Remove added columns
    op.drop_column('threats', 'severity_score')
    op.drop_column('threats', 'confidence_score')
    op.drop_column('threats', 'mitigation_status')
    op.drop_column('threats', 'assigned_to')
    
    op.drop_column('alerts', 'escalation_level')
    op.drop_column('alerts', 'assigned_to')
    op.drop_column('alerts', 'resolution_time')
    
    # Drop new tables
    op.drop_table('user_roles')
    op.drop_table('roles')
    op.drop_table('access_logs')
    op.drop_table('sessions')
    op.drop_table('users')
