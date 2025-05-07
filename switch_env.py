#!/usr/bin/env python
import os
import sys
import shutil

def switch_environment(env_name):
    """
    Switch between development and production environments
    by copying the appropriate .env file to .env
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    env_file = os.path.join(base_dir, ".env")
    
    if env_name.lower() == "dev" or env_name.lower() == "development":
        source_env = os.path.join(base_dir, ".env.development")
        env_type = "development"
    elif env_name.lower() == "prod" or env_name.lower() == "production":
        source_env = os.path.join(base_dir, ".env.production")
        env_type = "production"
    else:
        print(f"Unknown environment: {env_name}")
        print("Usage: python switch_env.py [dev|prod]")
        return 1
    
    if not os.path.exists(source_env):
        print(f"Error: {source_env} does not exist.")
        return 1
    
    # Make a backup of current .env if it exists
    if os.path.exists(env_file):
        backup_file = f"{env_file}.backup"
        shutil.copy2(env_file, backup_file)
        print(f"Backed up current .env to {backup_file}")
    
    # Copy the environment file
    shutil.copy2(source_env, env_file)
    print(f"Switched to {env_type} environment.")
    return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python switch_env.py [dev|prod]")
        sys.exit(1)
    
    sys.exit(switch_environment(sys.argv[1])) 