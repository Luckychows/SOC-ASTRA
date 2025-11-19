#!/usr/bin/env python3
"""
Test Script for AI-SOC Copilot Setup
Verifies all dependencies and connections
"""

import sys
import os
from dotenv import load_dotenv

def test_imports():
    """Test if all required packages are installed"""
    print("="*70)
    print("🔍 Testing Python Dependencies")
    print("="*70 + "\n")
    
    packages = [
        ("requests", "requests"),
        ("pandas", "pandas"),
        ("openai", "OpenAI"),
        ("langchain", "LangChain"),
        ("langchain_openai", "LangChain OpenAI"),
        ("pymilvus", "Milvus"),
        ("tiktoken", "TikToken"),
    ]
    
    failed = []
    
    for package, name in packages:
        try:
            __import__(package)
            print(f"✅ {name:<20} installed")
        except ImportError:
            print(f"❌ {name:<20} MISSING")
            failed.append(package)
    
    if failed:
        print(f"\n❌ Missing packages: {', '.join(failed)}")
        print("   Install with: pip install -r requirements.txt")
        return False
    else:
        print("\n✅ All dependencies installed")
        return True


def test_env():
    """Test environment configuration"""
    print("\n" + "="*70)
    print("🔍 Testing Environment Configuration")
    print("="*70 + "\n")
    
    load_dotenv()
    
    api_key = os.getenv("OPENAI_API_KEY")
    
    if not api_key:
        print("⚠️  OPENAI_API_KEY not found in .env file")
        print("   Create .env file from .env-sample and add your API key")
        return False
    
    print(f"✅ OPENAI_API_KEY found: {api_key[:15]}...{api_key[-5:]}")
    
    # Check optional configs
    configs = [
        ("OPENAI_MODEL", "gpt-4o"),
        ("OPENAI_EMBEDDING_MODEL", "text-embedding-3-large"),
        ("MILVUS_HOST", "localhost"),
        ("MILVUS_PORT", "19530"),
    ]
    
    for key, default in configs:
        value = os.getenv(key, default)
        print(f"   {key}: {value}")
    
    print("\n✅ Environment configured")
    return True


def test_openai():
    """Test OpenAI connection"""
    print("\n" + "="*70)
    print("🔍 Testing OpenAI Connection")
    print("="*70 + "\n")
    
    try:
        from openai import OpenAI
        load_dotenv()
        
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            print("❌ No API key available")
            return False
        
        client = OpenAI(api_key=api_key)
        
        # Test with a simple completion
        print("   Making test API call...")
        response = client.chat.completions.create(
            model="gpt-4o-mini",  # Use mini for testing
            messages=[{"role": "user", "content": "Say 'test'"}],
            max_tokens=5
        )
        
        print(f"✅ OpenAI API working")
        print(f"   Response: {response.choices[0].message.content}")
        return True
        
    except Exception as e:
        print(f"❌ OpenAI connection failed: {e}")
        return False


def test_docker():
    """Test Docker containers"""
    print("\n" + "="*70)
    print("🔍 Testing Docker Services")
    print("="*70 + "\n")
    
    import subprocess
    
    try:
        result = subprocess.run(
            ["docker-compose", "ps"],
            capture_output=True,
            text=True,
            check=True
        )
        
        output = result.stdout
        
        # Check for key services
        services = ["milvus-standalone", "milvus-etcd", "milvus-minio", "milvus-attu"]
        running = []
        stopped = []
        
        for service in services:
            if service in output and "Up" in output:
                running.append(service)
            else:
                stopped.append(service)
        
        if running:
            print(f"✅ Running services:")
            for svc in running:
                print(f"   - {svc}")
        
        if stopped:
            print(f"\n⚠️  Stopped services:")
            for svc in stopped:
                print(f"   - {svc}")
            print("\n   Start with: python setup_docker.py")
            return False
        
        return True
        
    except subprocess.CalledProcessError:
        print("❌ Docker Compose not found or not running")
        print("   Make sure Docker Desktop is installed and running")
        return False
    except FileNotFoundError:
        print("❌ docker-compose command not found")
        print("   Install Docker Compose")
        return False


def test_milvus():
    """Test Milvus connection"""
    print("\n" + "="*70)
    print("🔍 Testing Milvus Connection")
    print("="*70 + "\n")
    
    try:
        from pymilvus import connections, utility
        load_dotenv()
        
        host = os.getenv("MILVUS_HOST", "localhost")
        port = os.getenv("MILVUS_PORT", "19530")
        
        print(f"   Connecting to {host}:{port}...")
        connections.connect(
            alias="default",
            host=host,
            port=port,
            timeout=5
        )
        
        print("✅ Milvus connection successful")
        
        # List collections
        collections = utility.list_collections()
        if collections:
            print(f"   Found {len(collections)} collection(s):")
            for col in collections:
                print(f"   - {col}")
        else:
            print("   No collections yet (this is normal for first run)")
        
        connections.disconnect(alias="default")
        return True
        
    except Exception as e:
        print(f"❌ Milvus connection failed: {e}")
        print("   Make sure Docker containers are running")
        print("   Run: python setup_docker.py")
        return False


def main():
    """Run all tests"""
    print("\n")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║                                                                  ║")
    print("║         🧪 AI-SOC Copilot - Setup Verification               ║")
    print("║                                                                  ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print("\n")
    
    tests = [
        ("Dependencies", test_imports),
        ("Environment", test_env),
        ("OpenAI API", test_openai),
        ("Docker", test_docker),
        ("Milvus", test_milvus),
    ]
    
    results = {}
    
    for name, test_func in tests:
        try:
            results[name] = test_func()
        except Exception as e:
            print(f"\n❌ {name} test crashed: {e}")
            results[name] = False
    
    # Summary
    print("\n" + "="*70)
    print("📊 TEST SUMMARY")
    print("="*70 + "\n")
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status:<10} {name}")
    
    print(f"\n{passed}/{total} tests passed")
    
    if passed == total:
        print("\n" + "="*70)
        print("🎉 ALL TESTS PASSED - Ready to use AI-SOC Copilot!")
        print("="*70)
        print("\nRun: python main.py")
        return 0
    else:
        print("\n" + "="*70)
        print("⚠️  SOME TESTS FAILED - Please fix the issues above")
        print("="*70)
        return 1


if __name__ == "__main__":
    sys.exit(main())










