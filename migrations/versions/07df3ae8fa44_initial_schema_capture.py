"""Initial schema capture

Revision ID: 07df3ae8fa44
Revises: 
Create Date: 2025-08-29 23:13:20.180731

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '07df3ae8fa44'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Create document table
    op.create_table('document',
        sa.Column('id', sa.Text(), nullable=False),
        sa.Column('filename', sa.Text(), nullable=False),
        sa.Column('file_path', sa.Text(), nullable=False),
        sa.Column('file_hash', sa.Text(), nullable=False),
        sa.Column('pages', sa.Integer(), nullable=False),
        sa.Column('ocr_pages', sa.Integer(), nullable=False),
        sa.Column('tlp', sa.Text(), nullable=True),
        sa.Column('namespace', sa.Text(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create doc_chunk table
    op.create_table('doc_chunk',
        sa.Column('id', sa.Text(), nullable=False),
        sa.Column('document_id', sa.Text(), nullable=False),
        sa.Column('page', sa.Integer(), nullable=False),
        sa.Column('bbox', sa.JSON(), nullable=True),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('actors', sa.JSON(), nullable=True),
        sa.Column('techniques', sa.JSON(), nullable=True),
        sa.Column('cves', sa.JSON(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('embedding', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['document_id'], ['document.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create actor table
    op.create_table('actor',
        sa.Column('id', sa.Text(), nullable=False),
        sa.Column('mitre_gid', sa.Text(), nullable=True),
        sa.Column('names', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create technique table
    op.create_table('technique',
        sa.Column('id', sa.Text(), nullable=False),
        sa.Column('t_id', sa.Text(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('synonyms', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create cve table
    op.create_table('cve',
        sa.Column('id', sa.Text(), nullable=False),
        sa.Column('cve_id', sa.Text(), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create actor_cve table
    op.create_table('actor_cve',
        sa.Column('actor_id', sa.Text(), nullable=False),
        sa.Column('cve_id', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['actor.id'], ),
        sa.ForeignKeyConstraint(['cve_id'], ['cve.id'], ),
        sa.PrimaryKeyConstraint('actor_id', 'cve_id')
    )
    
    # Create cve_technique table
    op.create_table('cve_technique',
        sa.Column('cve_id', sa.Text(), nullable=False),
        sa.Column('technique_id', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['cve_id'], ['cve.id'], ),
        sa.ForeignKeyConstraint(['technique_id'], ['technique.id'], ),
        sa.PrimaryKeyConstraint('cve_id', 'technique_id')
    )
    
    # Create alias table
    op.create_table('alias',
        sa.Column('actor_id', sa.Text(), nullable=False),
        sa.Column('name', sa.Text(), nullable=False),
        sa.Column('source', sa.Text(), nullable=True),
        sa.Column('provenance', sa.JSON(), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=True),
        sa.Column('created_at', sa.TIMESTAMP(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.ForeignKeyConstraint(['actor_id'], ['actor.id'], ),
        sa.PrimaryKeyConstraint('actor_id', 'name')
    )
    
    # Create indexes
    op.create_index('idx_doc_chunk_document_id', 'doc_chunk', ['document_id'])
    op.create_index('idx_doc_chunk_page', 'doc_chunk', ['page'])
    op.create_index('idx_alias_actor_id', 'alias', ['actor_id'])
    op.create_index('idx_alias_name', 'alias', ['name'])
    op.create_index('idx_alias_source', 'alias', ['source'])
    op.create_index('idx_alias_confidence', 'alias', ['confidence'])


def downgrade() -> None:
    """Downgrade schema."""
    # Drop indexes
    op.drop_index('idx_alias_confidence', table_name='alias')
    op.drop_index('idx_alias_source', table_name='alias')
    op.drop_index('idx_alias_name', table_name='alias')
    op.drop_index('idx_alias_actor_id', table_name='alias')
    op.drop_index('idx_doc_chunk_page', table_name='doc_chunk')
    op.drop_index('idx_doc_chunk_document_id', table_name='doc_chunk')
    
    # Drop tables
    op.drop_table('cve_technique')
    op.drop_table('actor_cve')
    op.drop_table('alias')
    op.drop_table('cve')
    op.drop_table('technique')
    op.drop_table('actor')
    op.drop_table('doc_chunk')
    op.drop_table('document')
