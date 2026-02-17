import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';

// API Configuration (extracted)
import api, { API_BASE_URL, SESSION_TIMEOUT, SESSION_WARNING } from './api';

// Extracted Components
import Login from './components/auth/Login';
import IPadDetailViewer from './components/ipads/IPadDetailViewer';
import IPadsManagement from './components/ipads/IPadsManagement';
import StudentsManagement from './components/students/StudentsManagement';
import AssignmentsManagement from './components/assignments/AssignmentsManagement';
import ContractsManagement from './components/contracts/ContractsManagement';
import Settings from './components/settings/Settings';
import SessionTimer from './components/shared/SessionTimer';
import UserManagement from './components/users/UserManagement';

// Import UI components
import { Button } from './components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { toast } from 'sonner';
import { Toaster } from './components/ui/sonner';
import { Users, Tablet, FileText, Settings as SettingsIcon, LogOut } from 'lucide-react';

// Main Dashboard Component
const Dashboard = ({ onLogout, userRole, currentUsername }) => {
  const [activeTab, setActiveTab] = useState('students');
  const isAdmin = userRole === 'admin';
// Main Dashboard Component
const Dashboard = ({ onLogout, userRole, currentUsername }) => {
  const [activeTab, setActiveTab] = useState('students');
  const isAdmin = userRole === 'admin';

  return (
    <div className="min-h-screen bg-gray-50">
      <nav className="bg-ipad-dark-gray shadow-sm border-b border-ipad-beige">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <div className="flex-shrink-0 flex items-center">
                <div className="w-8 h-8 bg-gradient-to-br from-ipad-teal to-ipad-blue rounded-lg flex items-center justify-center">
                  <Tablet className="h-5 w-5 text-white" />
                </div>
                <span className="ml-3 text-xl font-bold bg-gradient-to-r from-ipad-teal to-ipad-blue bg-clip-text text-transparent">
                  iPad-Verwaltung
                </span>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-white">
                <User className="h-4 w-4" />
                <span className="text-sm font-medium">{currentUsername}</span>
                {isAdmin && (
                  <span className="ml-2 px-2 py-1 bg-gradient-to-r from-yellow-400 to-orange-500 text-white text-xs font-bold rounded-full">
                    ADMIN
                  </span>
                )}
              </div>
              <SessionTimer onLogout={onLogout} />
              <Button variant="outline" onClick={onLogout} className="flex items-center gap-2">
                <LogOut className="h-4 w-4" />
                Abmelden
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-8 px-4 sm:px-6 lg:px-8">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className={`grid w-full ${isAdmin ? 'grid-cols-6' : 'grid-cols-5'} mb-8`}>
            <TabsTrigger value="students" className="flex items-center gap-2">
              <Users className="h-4 w-4" />
              Schüler
            </TabsTrigger>
            <TabsTrigger value="ipads" className="flex items-center gap-2">
              <Tablet className="h-4 w-4" />
              iPads
            </TabsTrigger>
            <TabsTrigger value="assignments" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Zuordnungen
            </TabsTrigger>
            <TabsTrigger value="contracts" className="flex items-center gap-2">
              <FileText className="h-4 w-4" />
              Verträge
            </TabsTrigger>
            <TabsTrigger value="settings" className="flex items-center gap-2">
              <SettingsIcon className="h-4 w-4" />
              Einstellungen
            </TabsTrigger>
            {isAdmin && (
              <TabsTrigger value="users" className="flex items-center gap-2 bg-gradient-to-r from-yellow-400/10 to-orange-500/10">
                <Users className="h-4 w-4" />
                Benutzer
              </TabsTrigger>
            )}
          </TabsList>

          <TabsContent value="students">
            <StudentsManagement />
          </TabsContent>

          <TabsContent value="ipads">
            <IPadsManagement />
          </TabsContent>

          <TabsContent value="assignments">
            <AssignmentsManagement />
          </TabsContent>

          <TabsContent value="contracts">
            <ContractsManagement />
          </TabsContent>

          <TabsContent value="settings">
            <Settings />
          </TabsContent>

          {isAdmin && (
            <TabsContent value="users">
              <UserManagement />
            </TabsContent>
          )}
        </Tabs>
      </div>
    </div>
  );
};

// Main App Component
function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [userRole, setUserRole] = useState('user');
  const [currentUsername, setCurrentUsername] = useState('');
  const [loading, setLoading] = useState(true);
  const [sessionWarningShown, setSessionWarningShown] = useState(false);

  // Session timeout handler
  const checkSessionTimeout = useCallback(() => {
    const lastActivity = localStorage.getItem('lastActivity');
    if (!lastActivity) return;
    
    const timeSinceActivity = Date.now() - parseInt(lastActivity, 10);
    const timeUntilTimeout = SESSION_TIMEOUT - timeSinceActivity;
    
    // Show warning 5 minutes before timeout
    if (timeUntilTimeout <= SESSION_WARNING && timeUntilTimeout > 0 && !sessionWarningShown) {
      setSessionWarningShown(true);
      const minutesLeft = Math.ceil(timeUntilTimeout / 60000);
      toast.warning(`Ihre Session läuft in ${minutesLeft} Minute${minutesLeft > 1 ? 'n' : ''} ab. Bitte speichern Sie Ihre Arbeit.`, {
        duration: 10000,
      });
    }
    
    // Session expired
    if (timeUntilTimeout <= 0) {
      toast.error('Ihre Session ist abgelaufen. Sie werden zur Anmeldeseite weitergeleitet.');
      handleLogout();
    }
  }, [sessionWarningShown]);

  // Update last activity on user interaction
  const updateActivity = useCallback(() => {
    if (isAuthenticated) {
      localStorage.setItem('lastActivity', Date.now().toString());
      setSessionWarningShown(false);
    }
  }, [isAuthenticated]);

  useEffect(() => {
    const token = localStorage.getItem('token');
    const savedRole = localStorage.getItem('userRole');
    const savedUsername = localStorage.getItem('username');
    if (token) {
      setIsAuthenticated(true);
      setUserRole(savedRole || 'user');
      setCurrentUsername(savedUsername || '');
      
      // Initialize last activity if not set
      if (!localStorage.getItem('lastActivity')) {
        localStorage.setItem('lastActivity', Date.now().toString());
      }
    }
    setLoading(false);
    
    // Listener für automatischen Logout bei Session-Ablauf
    const handleSessionExpired = () => {
      handleLogout();
    };
    
    window.addEventListener('session-expired', handleSessionExpired);
    
    return () => {
      window.removeEventListener('session-expired', handleSessionExpired);
    };
  }, []);

  // Session timeout checker interval
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const interval = setInterval(checkSessionTimeout, 10000); // Check every 10 seconds
    return () => clearInterval(interval);
  }, [isAuthenticated, checkSessionTimeout]);

  // Activity tracker
  useEffect(() => {
    if (!isAuthenticated) return;
    
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    
    events.forEach(event => {
      window.addEventListener(event, updateActivity);
    });
    
    return () => {
      events.forEach(event => {
        window.removeEventListener(event, updateActivity);
      });
    };
  }, [isAuthenticated, updateActivity]);

  const handleLogin = (role, username) => {
    setIsAuthenticated(true);
    setUserRole(role);
    setCurrentUsername(username);
    localStorage.setItem('lastActivity', Date.now().toString());
    setSessionWarningShown(false);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('username');
    localStorage.removeItem('lastActivity');
    setIsAuthenticated(false);
    setUserRole('user');
    setCurrentUsername('');
    setSessionWarningShown(false);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-ipad-beige via-gray-50 to-ipad-teal/10 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-ipad-teal mx-auto"></div>
          <p className="mt-4 text-ipad-dark-gray">Lade Anwendung...</p>
        </div>
      </div>
    );
  }

  return (
    <Router>
      <div className="App">
        <Toaster richColors position="bottom-right" />
        <Routes>
          <Route 
            path="/" 
            element={
              isAuthenticated ? (
                <Dashboard 
                  onLogout={handleLogout} 
                  userRole={userRole} 
                  currentUsername={currentUsername}
                />
              ) : (
                <Login onLogin={handleLogin} />
              )
            } 
          />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;