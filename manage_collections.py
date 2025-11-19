#!/usr/bin/env python3
"""
Collection Management Utility
View, manage, and clean up Milvus collections
"""

import os
from pymilvus import connections, utility, Collection
from dotenv import load_dotenv

load_dotenv()

def connect_milvus():
    """Connect to Milvus"""
    host = os.getenv("MILVUS_HOST", "localhost")
    port = os.getenv("MILVUS_PORT", "19530")
    
    try:
        connections.connect(alias="default", host=host, port=port)
        print(f"✅ Connected to Milvus at {host}:{port}\n")
        return True
    except Exception as e:
        print(f"❌ Failed to connect: {e}")
        return False

def list_collections():
    """List all collections"""
    print("="*70)
    print("📚 AVAILABLE COLLECTIONS")
    print("="*70 + "\n")
    
    collections = utility.list_collections()
    
    if not collections:
        print("No collections found.\n")
        return []
    
    for idx, col_name in enumerate(collections, 1):
        try:
            col = Collection(col_name)
            col.load()
            num_entities = col.num_entities
            print(f"{idx}. {col_name}")
            print(f"   Vectors: {num_entities}")
            print(f"   Dataset: {col_name.replace('soc_', '').replace('_events', '').upper()}")
            print()
        except Exception as e:
            print(f"{idx}. {col_name} (Error: {e})\n")
    
    return collections

def drop_collection(col_name):
    """Drop a specific collection"""
    try:
        if utility.has_collection(col_name):
            utility.drop_collection(col_name)
            print(f"✅ Dropped collection: {col_name}")
            return True
        else:
            print(f"❌ Collection not found: {col_name}")
            return False
    except Exception as e:
        print(f"❌ Failed to drop: {e}")
        return False

def drop_all_collections():
    """Drop all collections"""
    collections = utility.list_collections()
    
    if not collections:
        print("No collections to drop.")
        return
    
    print(f"\n⚠️  About to drop {len(collections)} collection(s):")
    for col in collections:
        print(f"   - {col}")
    
    confirm = input("\nAre you sure? Type 'yes' to confirm: ").strip().lower()
    
    if confirm == 'yes':
        for col in collections:
            drop_collection(col)
        print(f"\n✅ Dropped all collections")
    else:
        print("\n❌ Cancelled")

def collection_stats(col_name):
    """Show detailed stats for a collection"""
    try:
        if not utility.has_collection(col_name):
            print(f"❌ Collection not found: {col_name}")
            return
        
        col = Collection(col_name)
        col.load()
        
        print("\n" + "="*70)
        print(f"📊 COLLECTION STATS: {col_name}")
        print("="*70 + "\n")
        
        print(f"Name: {col_name}")
        print(f"Total Vectors: {col.num_entities}")
        print(f"Schema Fields:")
        
        for field in col.schema.fields:
            print(f"   - {field.name}: {field.dtype}")
        
        print(f"\nIndexes:")
        indexes = col.indexes
        if indexes:
            for idx in indexes:
                print(f"   - {idx.field_name}: {idx.params}")
        else:
            print("   No indexes")
        
        print()
        
    except Exception as e:
        print(f"❌ Error: {e}")

def main():
    print("\n")
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║                                                                  ║")
    print("║           🗄️  Milvus Collection Manager                         ║")
    print("║                                                                  ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    print("\n")
    
    if not connect_milvus():
        return
    
    while True:
        collections = list_collections()
        
        print("="*70)
        print("OPTIONS")
        print("="*70)
        print("1. Refresh list")
        print("2. View collection details")
        print("3. Drop a specific collection")
        print("4. Drop ALL collections")
        print("5. Exit")
        print()
        
        choice = input("Select option (1-5): ").strip()
        
        if choice == "1":
            continue
        
        elif choice == "2":
            if not collections:
                print("\nNo collections available.\n")
                continue
            
            col_num = input(f"\nEnter collection number (1-{len(collections)}): ").strip()
            try:
                idx = int(col_num) - 1
                if 0 <= idx < len(collections):
                    collection_stats(collections[idx])
                else:
                    print("❌ Invalid number")
            except ValueError:
                print("❌ Invalid input")
        
        elif choice == "3":
            if not collections:
                print("\nNo collections available.\n")
                continue
            
            col_num = input(f"\nEnter collection number to drop (1-{len(collections)}): ").strip()
            try:
                idx = int(col_num) - 1
                if 0 <= idx < len(collections):
                    confirm = input(f"Drop '{collections[idx]}'? (y/n): ").strip().lower()
                    if confirm == 'y':
                        drop_collection(collections[idx])
                else:
                    print("❌ Invalid number")
            except ValueError:
                print("❌ Invalid input")
        
        elif choice == "4":
            drop_all_collections()
        
        elif choice == "5":
            print("\n👋 Goodbye!\n")
            break
        
        else:
            print("\n❌ Invalid option\n")
    
    connections.disconnect(alias="default")

if __name__ == "__main__":
    main()









