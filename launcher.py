#!/usr/bin/env python3
"""
SOC-ASTRA Unified Launcher
All-in-one script for setup, cleanup, and running the system
"""

import subprocess
import sys
import time
import os
from pathlib import Path


def print_banner():
    """Print banner"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║              🛡️  SOC-ASTRA LAUNCHER                              ║
║              Unified Setup & Management Tool                     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
    """)


def check_command(command):
    """Check if a command exists"""
    try:
        subprocess.run([command, "--version"], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE,
                      check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def get_docker_compose_cmd():
    """Get the correct docker-compose command (v1 or v2)"""
    # Try docker compose (v2) first
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0:
            return "docker compose"
    except:
        pass
    
    # Fall back to docker-compose (v1)
    if check_command("docker-compose"):
        return "docker-compose"
    
    return None


def check_docker_running():
    """Check if Docker is running"""
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False


def check_milvus_ready(max_retries=10, retry_delay=5):
    """Check if Milvus is ready to accept connections"""
    try:
        from pymilvus import connections
        
        for attempt in range(max_retries):
            try:
                connections.connect(
                    alias="test_connection",
                    host='localhost',
                    port='19530',
                    timeout=3
                )
                connections.disconnect(alias="test_connection")
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    print(f"   ⏳ Attempt {attempt + 1}/{max_retries}: Milvus not ready yet, waiting {retry_delay}s...")
                    time.sleep(retry_delay)
                else:
                    print(f"   ❌ Milvus failed to start after {max_retries} attempts")
                    return False
        return False
    except ImportError:
        print("   ⚠️  Cannot check Milvus (pymilvus not installed)")
        return True  # Assume it's ready if we can't check


def setup_docker():
    """Setup and start Docker containers"""
    print("\n" + "="*70)
    print("🐳 DOCKER SETUP")
    print("="*70 + "\n")
    
    # Check Docker
    print("🔍 Checking prerequisites...")
    if not check_command("docker"):
        print("❌ Docker is not installed or not in PATH")
        print("   Please install Docker Desktop from: https://www.docker.com/products/docker-desktop")
        return False
    print("✅ Docker is installed")
    
    # Check Docker Compose
    compose_cmd = get_docker_compose_cmd()
    if not compose_cmd:
        print("❌ Docker Compose is not installed")
        print("   Install: https://docs.docker.com/compose/install/")
        return False
    print(f"✅ Docker Compose is installed ({compose_cmd})")
    
    # Check if docker-compose.yml exists
    if not os.path.exists("docker-compose.yml"):
        print("❌ docker-compose.yml not found in current directory")
        print(f"   Current dir: {os.getcwd()}")
        return False
    print("✅ docker-compose.yml found")
    
    print("\n📥 Pulling Docker images...")
    try:
        result = subprocess.run(f"{compose_cmd} pull", shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ Images pulled")
        else:
            print("⚠️  Pull had warnings, continuing...")
    except Exception as e:
        print(f"⚠️  Pull failed: {e}, continuing...")
    
    print("\n🚀 Starting containers with docker-compose...")
    try:
        result = subprocess.run(f"{compose_cmd} up -d", shell=True, check=True, capture_output=True, text=True)
        print("✅ Containers started")
        print("\n📋 Container output:")
        if result.stdout:
            for line in result.stdout.strip().split('\n')[-5:]:  # Show last 5 lines
                print(f"   {line}")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to start containers")
        print(f"   Error: {e.stderr if e.stderr else str(e)}")
        return False
    
    print("\n⏳ Waiting for Milvus to be ready (this may take up to 100 seconds)...")
    if not check_milvus_ready(max_retries=10, retry_delay=10):
        print("\n❌ Milvus did not start properly")
        print("\nTroubleshooting:")
        print(f"  1. Check Docker logs: {compose_cmd} logs milvus")
        print(f"  2. Check all services: {compose_cmd} ps")
        print(f"  3. Restart Docker: {compose_cmd} restart")
        print("  4. Check if ports are available: netstat -an | grep 19530")
        return False
    print("   ✅ Milvus is ready!")
    
    print("\n📊 Container status:")
    compose_cmd = get_docker_compose_cmd()
    if compose_cmd:
        subprocess.run(f"{compose_cmd} ps", shell=True)
    
    print("\n✅ Docker setup complete!")
    print("\nServices available:")
    print("  🗄️  Milvus Vector DB:  localhost:19530")
    print("  🎨 Attu Admin UI:      http://localhost:8000")
    print("  📦 MinIO Console:      http://localhost:9001")
    
    return True


def cleanup_milvus():
    """Cleanup Milvus collections"""
    print("\n" + "="*70)
    print("🧹 MILVUS CLEANUP")
    print("="*70 + "\n")
    
    try:
        from pymilvus import connections, utility
        
        # Connect to Milvus
        print("🔗 Connecting to Milvus...")
        connections.connect(host='localhost', port='19530')
        print("✅ Connected")
        
        # List collections
        collections = utility.list_collections()
        print(f"\n📊 Found {len(collections)} collections")
        
        if not collections:
            print("✅ No collections to clean up")
            connections.disconnect(alias="default")
            return True
        
        print("\nCollections:")
        for i, col in enumerate(collections, 1):
            print(f"  {i}. {col}")
        
        # Find SOC collections
        soc_collections = [c for c in collections if 'soc' in c.lower()]
        
        if soc_collections:
            print(f"\n🗑️  Dropping {len(soc_collections)} SOC collections:")
            for collection in soc_collections:
                print(f"   - Dropping: {collection}")
                utility.drop_collection(collection)
                print(f"   ✅ Dropped: {collection}")
            print(f"\n✅ Cleanup complete! Dropped {len(soc_collections)} collections")
        else:
            print("\n✅ No SOC collections found")
        
        connections.disconnect(alias="default")
        return True
        
    except ImportError:
        print("❌ pymilvus not installed. Run: pip install -r requirements.txt")
        return False
    except Exception as e:
        print(f"❌ Cleanup failed: {e}")
        print("   Make sure Milvus is running")
        return False


def check_env_file():
    """Check and setup .env file"""
    print("\n" + "="*70)
    print("⚙️  ENVIRONMENT CONFIGURATION")
    print("="*70 + "\n")
    
    if not os.path.exists(".env"):
        print("⚠️  .env file not found!")
        
        # Create basic .env
        print("📝 Creating .env file...")
        env_content = """# SOC-ASTRA Configuration
OPENAI_API_KEY=sk-your-api-key-here
OPENAI_MODEL=gpt-4o
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
ENABLE_RAG=true
MILVUS_HOST=localhost
MILVUS_PORT=19530
ANALYSIS_WORKERS=2
DATABASE_PATH=./data/incidents.db
KNOWLEDGE_BASE_COLLECTION=soc_knowledge_base
"""
        with open(".env", "w") as f:
            f.write(env_content)
        
        print("✅ Created .env file")
        print("\n⚠️  IMPORTANT: Edit .env and add your OpenAI API key!")
        print("   The file is located at: .env")
        
        choice = input("\n   Open .env now? (y/n): ").strip().lower()
        if choice == 'y':
            if sys.platform == 'win32':
                os.system("notepad .env")
            else:
                os.system("${EDITOR:-nano} .env")
        
        print("\n   After adding your API key, run this script again.")
        return False
    
    # Check if API key is set
    with open(".env", "r") as f:
        content = f.read()
        if "sk-your-api-key-here" in content or "OPENAI_API_KEY=" not in content:
            print("⚠️  OpenAI API key not set in .env file!")
            print("   Please edit .env and add your API key")
            return False
    
    print("✅ Environment configured")
    return True


def stop_docker():
    """Stop Docker containers"""
    print("\n" + "="*70)
    print("⏸️  STOPPING DOCKER CONTAINERS")
    print("="*70 + "\n")
    
    compose_cmd = get_docker_compose_cmd()
    if not compose_cmd:
        print("❌ Docker Compose not found")
        return False
    
    try:
        subprocess.run(f"{compose_cmd} stop", shell=True, check=True)
        print("✅ Containers stopped")
        return True
    except:
        print("❌ Failed to stop containers")
        return False


def reset_docker():
    """Reset Docker - stop containers and remove volumes"""
    print("\n" + "="*70)
    print("🔄 RESET DOCKER (REMOVES ALL DATA)")
    print("="*70 + "\n")
    
    confirm = input("⚠️  This will delete ALL Milvus data. Continue? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print("❌ Reset cancelled")
        return False
    
    compose_cmd = get_docker_compose_cmd()
    if not compose_cmd:
        print("❌ Docker Compose not found")
        return False
    
    print("\n🛑 Stopping and removing containers...")
    try:
        subprocess.run(f"{compose_cmd} down -v", shell=True, check=True)
        print("✅ Containers and volumes removed")
        print("\n💡 Run Quick Start to rebuild everything fresh")
        return True
    except Exception as e:
        print(f"❌ Failed to reset: {e}")
        return False


def restart_docker():
    """Restart Docker containers"""
    print("\n" + "="*70)
    print("🔄 RESTARTING DOCKER CONTAINERS")
    print("="*70 + "\n")
    
    try:
        subprocess.run("docker-compose restart", shell=True, check=True)
        print("✅ Containers restarted")
        time.sleep(10)
        return True
    except:
        print("❌ Failed to restart containers")
        return False


def show_status():
    """Show system status"""
    print("\n" + "="*70)
    print("📊 SYSTEM STATUS")
    print("="*70 + "\n")
    
    # Docker status
    print("🐳 Docker:")
    if check_docker_running():
        print("   ✅ Running")
        subprocess.run("docker-compose ps", shell=True)
    else:
        print("   ❌ Not running")
    
    # Milvus collections
    print("\n🗄️  Milvus Collections:")
    try:
        from pymilvus import connections, utility
        connections.connect(host='localhost', port='19530')
        collections = utility.list_collections()
        if collections:
            for col in collections:
                print(f"   - {col}")
        else:
            print("   (empty)")
        connections.disconnect(alias="default")
    except:
        print("   ❌ Cannot connect")
    
    # Database
    print("\n💾 Database:")
    db_path = "./data/incidents.db"
    if os.path.exists(db_path):
        size = os.path.getsize(db_path) / 1024
        print(f"   ✅ {db_path} ({size:.1f} KB)")
    else:
        print("   ⚠️  Not created yet")
    
    print()


def run_web_app():
    """Run the web application"""
    print("\n" + "="*70)
    print("🚀 STARTING WEB APPLICATION")
    print("="*70 + "\n")
    
    print("Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop\n")
    print("="*70 + "\n")
    
    try:
        subprocess.run([sys.executable, "web_app.py"])
    except KeyboardInterrupt:
        print("\n\n⚠️  Stopped by user")
    except Exception as e:
        print(f"\n❌ Error: {e}")


def show_menu():
    """Show main menu"""
    print("\n" + "="*70)
    print("📋 MAIN MENU")
    print("="*70 + "\n")
    
    print("1. 🚀 Quick Start (Setup + Run)")
    print("2. 🐳 Setup Docker Only")
    print("3. 🧹 Cleanup Milvus Collections")
    print("4. ▶️  Run Web Application")
    print("5. 📊 Show System Status")
    print("6. ⏸️  Stop Docker")
    print("7. 🔄 Restart Docker")
    print("8. 🗑️  Reset Docker (Remove Volumes)")
    print("9. 🔧 Check Environment Config")
    print("0. ❌ Exit")
    
    print("\n" + "="*70)
    choice = input("Select option (0-9): ").strip()
    
    return choice


def quick_start():
    """Quick start - setup and run everything"""
    print("\n" + "="*70)
    print("🚀 QUICK START MODE")
    print("="*70 + "\n")
    
    # Check environment
    print("1️⃣  Checking environment configuration...")
    if not check_env_file():
        print("\n❌ Please configure .env file first")
        return False
    
    # Setup Docker
    print("\n2️⃣  Starting Docker containers...")
    
    # Always run setup_docker to ensure containers are up
    # (Docker might be running but containers might not be)
    if not setup_docker():
        print("\n❌ Docker setup failed")
        return False
    
    # Verify Milvus is ready
    print("\n3️⃣  Verifying Milvus is ready...")
    if not check_milvus_ready(max_retries=6, retry_delay=10):
        print("❌ Milvus is not responding")
        print("\n💡 Try restarting Docker:")
        print("   docker-compose restart")
        return False
    print("✅ Milvus is ready")
    
    # Cleanup old collections
    print("\n4️⃣  Cleaning up old Milvus collections...")
    cleanup_milvus()
    
    # Run web app
    print("\n5️⃣  Starting web application...")
    print("\n" + "="*70)
    print("✅ READY TO START!")
    print("="*70)
    print("\n📌 Docker is running in the background")
    print("📌 Dashboard will be at: http://localhost:5000")
    print("📌 Press Ctrl+C to stop the web server")
    print("📌 Docker will keep running after you stop")
    print("\n⏳ Starting in 3 seconds...")
    print("="*70 + "\n")
    
    time.sleep(3)
    run_web_app()
    return True


def main():
    """Main execution"""
    print_banner()
    
    # Check if run directly with no args - do quick start
    if len(sys.argv) == 1:
        print("💡 Tip: Running in Quick Start mode")
        print("   For full menu, use: python launcher.py --menu\n")
        time.sleep(2)
        quick_start()
        return
    
    # Show menu for interactive mode
    while True:
        choice = show_menu()
        
        if choice == '1':
            # Quick Start
            if quick_start():
                break  # Exit menu after successful quick start
            
        elif choice == '2':
            # Setup Docker
            setup_docker()
            
        elif choice == '3':
            # Cleanup
            cleanup_milvus()
            
        elif choice == '4':
            # Run web app
            if not check_env_file():
                continue
            if not check_docker_running():
                print("\n⚠️  Docker is not running!")
                print("   Start Docker first (option 2)")
                continue
            run_web_app()
            
        elif choice == '5':
            # Status
            show_status()
            
        elif choice == '6':
            # Stop Docker
            stop_docker()
            
        elif choice == '7':
            # Restart Docker
            restart_docker()
            
        elif choice == '8':
            # Reset Docker
            reset_docker()
            
        elif choice == '9':
            # Check environment
            check_env_file()
            
        elif choice == '0':
            # Exit
            print("\n👋 Goodbye!\n")
            break
            
        else:
            print("\n❌ Invalid choice. Please select 1-9.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user\n")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

