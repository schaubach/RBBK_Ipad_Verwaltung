import React, { useState, useEffect, useCallback } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';

// API Configuration (extracted)
import api, { SESSION_TIMEOUT, SESSION_WARNING } from './api';

// Extracted Components
import Login from './components/auth/Login';
import IPadsManagement from './components/ipads/IPadsManagement';
import StudentsManagement from './components/students/StudentsManagement';
import ContractsManagement from './components/contracts/ContractsManagement';
import Settings from './components/settings/Settings';
import SessionTimer from './components/shared/SessionTimer';
import UserManagement from './components/users/UserManagement';
import { BildungsgangUmschalter } from './components/shared/BildungsgangUmschalter';
import {
  BildungsgangAnsichtProvider,
  ANSICHT_SPEICHER_SCHLUESSEL,
} from './hooks/BildungsgangAnsicht';

// Import UI components
import { Button } from './components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from './components/ui/tabs';
import { toast } from 'sonner';
import { Toaster } from './components/ui/sonner';
import { Users, Tablet, FileText, Settings as SettingsIcon, LogOut, User, ShieldCheck } from 'lucide-react';

// Main Dashboard Component
const Dashboard = ({ onLogout, userRole, currentUsername }) => {
  const [activeTab, setActiveTab] = useState('students');
  const isAdmin = userRole === 'admin';

  return (
    <BildungsgangAnsichtProvider username={currentUsername} isAdmin={isAdmin}>
    <div className="min-h-screen bg-gray-50">
      {/* Auf schmalen Bildschirmen (Handy, iPad hochkant) bricht die Kopfzeile um, statt
          über den Rand zu ragen - vorher war die ganze Seite breiter als das Display und
          "Abmelden" abgeschnitten. */}
      <nav className="bg-ipad-dark-gray shadow-sm border-b border-ipad-beige">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 py-3 min-h-16">
            <div className="flex items-center min-w-0">
              <div className="flex-shrink-0 flex items-center">
                <div className="w-8 h-8 bg-gradient-to-br from-ipad-teal to-ipad-blue rounded-lg flex items-center justify-center">
                  <Tablet className="h-5 w-5 text-white" />
                </div>
                <span className="ml-3 text-lg sm:text-xl font-bold bg-gradient-to-r from-ipad-teal to-ipad-blue bg-clip-text text-transparent whitespace-nowrap">
                  iPad-Verwaltung
                </span>
              </div>
            </div>
            <div className="flex flex-wrap items-center justify-end gap-x-3 gap-y-2 sm:gap-x-4 min-w-0">
              <div className="flex items-center gap-2 text-white min-w-0">
                <User className="h-4 w-4 flex-shrink-0" />
                <span className="text-sm font-medium truncate">{currentUsername}</span>
                {isAdmin && (
                  <span className="ml-1 px-2 py-1 bg-gradient-to-r from-yellow-400 to-orange-500 text-white text-xs font-bold rounded-full">
                    ADMIN
                  </span>
                )}
              </div>
              {/* Die Ansicht ist ein Arbeitszusammenhang, kein Listenfilter: hier
                  eingestellt, folgen Lernende, Geräte und Verträge gemeinsam. */}
              <BildungsgangUmschalter />
              <SessionTimer onLogout={onLogout} />
              <Button
                variant="outline"
                onClick={onLogout}
                className="flex items-center gap-2"
                aria-label="Abmelden"
                title="Abmelden"
              >
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline">Abmelden</span>
              </Button>
            </div>
          </div>
        </div>
      </nav>

      <div className="max-w-7xl mx-auto py-4 sm:py-8 px-3 sm:px-6 lg:px-8">
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className={`grid w-full h-auto ${isAdmin ? 'grid-cols-5' : 'grid-cols-4'} mb-6 sm:mb-8`}>
            {[
              { value: 'students', icon: Users, lang: 'Lernende', kurz: 'Lernende' },
              { value: 'ipads', icon: Tablet, lang: 'iPads', kurz: 'iPads' },
              { value: 'contracts', icon: FileText, lang: 'Verträge', kurz: 'Verträge' },
              { value: 'settings', icon: SettingsIcon, lang: 'Einstellungen', kurz: 'Einst.' },
              ...(isAdmin ? [{ value: 'users', icon: ShieldCheck, lang: 'Admin', kurz: 'Admin', admin: true }] : []),
            ].map(({ value, icon: Icon, lang, kurz, admin }) => (
              <TabsTrigger
                key={value}
                value={value}
                aria-label={lang}
                title={lang}
                className={`flex flex-col sm:flex-row items-center gap-0.5 sm:gap-2 px-1 sm:px-3 py-1.5 text-[11px] sm:text-sm min-w-0 ${
                  admin ? 'bg-gradient-to-r from-yellow-400/10 to-orange-500/10' : ''
                }`}
              >
                <Icon className="h-4 w-4 flex-shrink-0" />
                <span className="sm:hidden truncate max-w-full">{kurz}</span>
                <span className="hidden sm:inline">{lang}</span>
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="students">
            <StudentsManagement />
          </TabsContent>

          <TabsContent value="ipads">
            <IPadsManagement isAdmin={isAdmin} />
          </TabsContent>

          <TabsContent value="contracts">
            <ContractsManagement />
          </TabsContent>

          <TabsContent value="settings">
            <Settings isAdmin={isAdmin} />
          </TabsContent>

          {isAdmin && (
            <TabsContent value="users">
              <UserManagement />
            </TabsContent>
          )}
        </Tabs>
      </div>
    </div>
    </BildungsgangAnsichtProvider>
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

  const handleLogout = async () => {
    // Call server to delete HttpOnly cookie
    try {
      await api.post('/auth/logout');
    } catch (error) {
      // Ignore errors - logout locally anyway
      console.log('Logout request failed, clearing local state anyway');
    }

    // Clear local storage
    localStorage.removeItem('token');
    localStorage.removeItem('userRole');
    localStorage.removeItem('username');
    localStorage.removeItem('lastActivity');
    // Die eingeengte Ansicht endet mit der Sitzung: nach einer Anmeldung soll niemand
    // in einem Ausschnitt landen, den er vor Tagen eingestellt hat.
    localStorage.removeItem(ANSICHT_SPEICHER_SCHLUESSEL);
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
