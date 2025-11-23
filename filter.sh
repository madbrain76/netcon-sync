# Create a local venv
python3 -m venv ~/venv-git-filter-repo

# Activate it
source ~/venv-git-filter-repo/bin/activate

# Install git-filter-repo inside the venv
pip install git-filter-repo

# Now run it
git filter-repo --path-glob 'local_test_*.py' --invert-paths

# Deactivate when done
deactivate

