"""refresh token

Revision ID: 2b290218db2b
Revises: 0f6e820a0e3b
Create Date: 2023-08-21 22:22:20.087849

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2b290218db2b'
down_revision: Union[str, None] = '0f6e820a0e3b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_users_id', table_name='users')
    op.drop_index('ix_users_username', table_name='users')
    op.drop_table('users')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('users',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('username', sa.VARCHAR(), nullable=True),
    sa.Column('hashed_password', sa.VARCHAR(), nullable=True),
    sa.Column('user_auth_token', sa.VARCHAR(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_users_username', 'users', ['username'], unique=False)
    op.create_index('ix_users_id', 'users', ['id'], unique=False)
    # ### end Alembic commands ###