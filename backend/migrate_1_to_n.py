#!/usr/bin/env python3
"""
Migration Script: 1:1 zu 1:n Beziehung (Schüler → iPads)

Entfernt das Feld 'current_assignment_id' aus allen Schüler-Dokumenten.
Die Zuordnungen werden nur noch über die Assignment-Collection verwaltet.
"""
import asyncio
import os
import sys
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

async def migrate():
    print("=" * 60)
    print("MIGRATION: 1:1 → 1:n Beziehung (Schüler → iPads)")
    print("=" * 60)
    print()
    
    # Connect to MongoDB
    mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017/iPadDatabase')
    db_name = os.environ.get('IPAD_DB_NAME', 'iPadDatabase')
    
    print(f"📡 Verbinde mit MongoDB: {mongo_url}")
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]
    
    try:
        # Check how many students have current_assignment_id
        students_with_assignment = await db.students.count_documents({
            "current_assignment_id": {"$exists": True, "$ne": None}
        })
        
        total_students = await db.students.count_documents({})
        
        print(f"\n📊 Statistik vor Migration:")
        print(f"   Gesamt Schüler: {total_students}")
        print(f"   Mit current_assignment_id: {students_with_assignment}")
        print()
        
        if students_with_assignment == 0:
            print("✅ Keine Migration notwendig - Feld existiert nicht mehr!")
            return
        
        # Confirm migration
        print("⚠️  Diese Migration wird das Feld 'current_assignment_id' aus allen Schüler-Dokumenten entfernen.")
        print("   Die Zuordnungen bleiben über die Assignment-Collection erhalten.")
        print()
        
        # Perform migration
        print("🔄 Starte Migration...")
        result = await db.students.update_many(
            {"current_assignment_id": {"$exists": True}},
            {"$unset": {"current_assignment_id": ""}}
        )
        
        print(f"\n✅ Migration abgeschlossen!")
        print(f"   Modifizierte Dokumente: {result.modified_count}")
        print()
        
        # Verify migration
        remaining = await db.students.count_documents({
            "current_assignment_id": {"$exists": True}
        })
        
        if remaining == 0:
            print("✅ Verifizierung erfolgreich - Kein 'current_assignment_id' mehr vorhanden!")
        else:
            print(f"⚠️  Warnung: {remaining} Dokumente haben noch 'current_assignment_id'")
        
        print()
        print("=" * 60)
        print("Migration erfolgreich abgeschlossen! 🎉")
        print("=" * 60)
        
    except Exception as e:
        print(f"\n❌ Fehler bei Migration: {str(e)}")
        sys.exit(1)
    finally:
        client.close()

if __name__ == "__main__":
    asyncio.run(migrate())
