import os
from git import Repo, GitCommandError
from typing import Optional

class GitManager:
    def __init__(self, repo_path: str):
        """Initialize GitManager with the repository path."""
        self.repo_path = repo_path
        self._repo: Optional[Repo] = None

    def initialize_repo(self) -> bool:
        """Initialize a new git repository if it doesn't exist."""
        try:
            if not os.path.exists(os.path.join(self.repo_path, '.git')):
                self._repo = Repo.init(self.repo_path)
                return True
            self._repo = Repo(self.repo_path)
            return True
        except GitCommandError as e:
            print(f"Error initializing git repository: {e}")
            return False

    def commit_changes(self, message: str) -> bool:
        """Commit all changes in the repository."""
        try:
            if not self._repo:
                return False

            # Add all changes
            self._repo.index.add('*')
            
            # Check if there are changes to commit
            if self._repo.is_dirty(untracked_files=True):
                self._repo.index.commit(message)
                return True
            return False
        except GitCommandError as e:
            print(f"Error committing changes: {e}")
            return False

    def get_history(self, max_count: int = 10) -> list:
        """Get commit history with detailed information about changes."""
        try:
            if not self._repo:
                return []
            
            commits = []
            for commit in self._repo.iter_commits(max_count=max_count):
                # Get the diff of this commit
                diffs = []
                if commit.parents:
                    for diff in commit.parents[0].diff(commit):
                        if diff.a_path:
                            diffs.append({
                                'path': diff.a_path,
                                'change_type': diff.change_type
                            })

                commits.append({
                    'hash': commit.hexsha,
                    'message': commit.message,
                    'author': str(commit.author),
                    'date': commit.committed_datetime,
                    'changes': diffs
                })
            return commits
        except GitCommandError as e:
            print(f"Error getting history: {e}")
            return [] 