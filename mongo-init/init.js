// MongoDB Initialisierungsskript
print('Initialisiere iPad-Verwaltung Datenbank...');

// Wechsle zur iPadDatabase
db = db.getSiblingDB('iPadDatabase');

// Erstelle Kollektionen mit Indizes für bessere Performance
db.createCollection('students');
db.createCollection('ipads');
db.createCollection('assignments');
db.createCollection('contracts');
db.createCollection('users');

// Erstelle Indizes
print('Erstelle Indizes...');

// Students Indizes
db.students.createIndex({ "id": 1 }, { unique: true });
db.students.createIndex({ "sus_vorn": 1, "sus_nachn": 1 });
db.students.createIndex({ "sus_kl": 1 });
db.students.createIndex({ "current_assignment_id": 1 });

// iPads Indizes
db.ipads.createIndex({ "id": 1 }, { unique: true });
db.ipads.createIndex({ "itnr": 1 }, { unique: true });
db.ipads.createIndex({ "status": 1 });
db.ipads.createIndex({ "current_assignment_id": 1 });

// Assignments Indizes
db.assignments.createIndex({ "id": 1 }, { unique: true });
db.assignments.createIndex({ "student_id": 1 });
db.assignments.createIndex({ "ipad_id": 1 });
db.assignments.createIndex({ "itnr": 1 });
db.assignments.createIndex({ "is_active": 1 });
db.assignments.createIndex({ "contract_id": 1 });

// Contracts Indizes
db.contracts.createIndex({ "id": 1 }, { unique: true });
db.contracts.createIndex({ "assignment_id": 1 });
db.contracts.createIndex({ "itnr": 1 });
db.contracts.createIndex({ "is_active": 1 });

// Users Indizes
db.users.createIndex({ "id": 1 }, { unique: true });
db.users.createIndex({ "username": 1 }, { unique: true });

print('Datenbank-Initialisierung abgeschlossen!');
print('Standard-Admin-Benutzer muss über /api/auth/setup erstellt werden.');