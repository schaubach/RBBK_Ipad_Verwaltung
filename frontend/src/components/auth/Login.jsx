import React, { useState, useEffect } from 'react';
import axios from 'axios';
import api, { API_BASE_URL } from '../../api';
import { Button } from '../ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/card';
import { Input } from '../ui/input';
import { Label } from '../ui/label';
import { toast } from 'sonner';
import { Tablet, AlertTriangle } from 'lucide-react';

const Login = ({ onLogin }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [showForcePasswordChange, setShowForcePasswordChange] = useState(false);
  const [tempToken, setTempToken] = useState(null);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    
    try {
      const response = await api.post('/auth/login', { username, password });
      const { access_token, role, username: loggedInUsername, force_password_change } = response.data;
      
      if (force_password_change) {
        setTempToken(access_token);
        setShowForcePasswordChange(true);
        toast.info('Sie müssen Ihr Passwort ändern, bevor Sie fortfahren können');
        setLoading(false);
        return;
      }
      
      localStorage.setItem('token', access_token);
      localStorage.setItem('userRole', role);
      localStorage.setItem('username', loggedInUsername);
      onLogin(role, loggedInUsername);
      toast.success(`Erfolgreich angemeldet als ${role === 'admin' ? 'Administrator' : 'Benutzer'}!`);
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleForcePasswordChange = async (e) => {
    e.preventDefault();
    
    if (newPassword.length < 6) {
      toast.error('Das Passwort muss mindestens 6 Zeichen lang sein');
      return;
    }
    
    if (newPassword !== confirmPassword) {
      toast.error('Die Passwörter stimmen nicht überein');
      return;
    }
    
    setLoading(true);
    
    try {
      await axios.put(
        `${API_BASE_URL}/auth/change-password-forced`,
        { new_password: newPassword },
        { headers: { Authorization: `Bearer ${tempToken}` } }
      );
      
      toast.success('Passwort erfolgreich geändert! Bitte melden Sie sich mit Ihrem neuen Passwort an.');
      setShowForcePasswordChange(false);
      setTempToken(null);
      setNewPassword('');
      setConfirmPassword('');
      setPassword('');
    } catch (error) {
      toast.error(error.response?.data?.detail || 'Fehler beim Ändern des Passworts');
    } finally {
      setLoading(false);
    }
  };

  const checkSetup = async () => {
    try {
      const response = await api.post('/auth/setup');
      if (response.data.message.includes('Admin user created')) {
        toast.success('Setup completed! Please login with admin/admin123');
      }
    } catch (error) {
      // Setup likely already done
    }
  };

  useEffect(() => {
    checkSetup();
  }, []);

  // Force Password Change Dialog
  if (showForcePasswordChange) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-ipad-beige via-gray-50 to-ipad-teal/20 flex items-center justify-center p-4">
        <Card className="w-full max-w-md shadow-2xl border-yellow-500/50">
          <CardHeader className="text-center">
            <div className="w-16 h-16 bg-yellow-500 rounded-full flex items-center justify-center mx-auto mb-4">
              <AlertTriangle className="h-8 w-8 text-white" />
            </div>
            <CardTitle className="text-2xl font-bold text-yellow-600">
              Passwort ändern erforderlich
            </CardTitle>
            <CardDescription className="text-ipad-dark-gray">
              Ihr Administrator hat Ihr Passwort zurückgesetzt. Bitte wählen Sie ein neues Passwort.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleForcePasswordChange} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="new-password">Neues Passwort</Label>
                <Input
                  id="new-password"
                  type="password"
                  placeholder="Neues Passwort eingeben (min. 6 Zeichen)"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  className="transition-all duration-200 focus:ring-2 focus:ring-yellow-500"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="confirm-password">Passwort bestätigen</Label>
                <Input
                  id="confirm-password"
                  type="password"
                  placeholder="Passwort wiederholen"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  className="transition-all duration-200 focus:ring-2 focus:ring-yellow-500"
                />
              </div>
              <Button 
                type="submit" 
                className="w-full bg-yellow-500 hover:bg-yellow-600 text-white transition-all duration-200"
                disabled={loading}
              >
                {loading ? 'Wird geändert...' : 'Passwort ändern'}
              </Button>
            </form>
            <div className="mt-4 text-xs text-gray-500 text-center">
              Nach der Passwortänderung müssen Sie sich erneut anmelden.
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-ipad-beige via-gray-50 to-ipad-teal/20 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-2xl border-ipad-beige/20">
        <CardHeader className="text-center">
          <div className="w-16 h-16 bg-gradient-to-br from-ipad-teal to-ipad-blue rounded-full flex items-center justify-center mx-auto mb-4">
            <Tablet className="h-8 w-8 text-white" />
          </div>
          <CardTitle className="text-2xl font-bold bg-gradient-to-r from-ipad-teal to-ipad-blue bg-clip-text text-transparent">
            iPad-Verwaltung
          </CardTitle>
          <CardDescription className="text-ipad-dark-gray">
            Melden Sie sich an, um fortzufahren
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username">Benutzername</Label>
              <Input
                id="username"
                type="text"
                placeholder="Benutzername eingeben"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
                className="transition-all duration-200 focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Passwort</Label>
              <Input
                id="password"
                type="password"
                placeholder="Passwort eingeben"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                className="transition-all duration-200 focus:ring-2 focus:ring-purple-500"
              />
            </div>
            <Button 
              type="submit" 
              className="w-full bg-gradient-to-r from-ipad-teal to-ipad-dark-blue hover:from-ipad-blue hover:to-ipad-dark-gray transition-all duration-200"
              disabled={loading}
            >
              {loading ? 'Anmeldung läuft...' : 'Anmelden'}
            </Button>
          </form>
          <div className="mt-6 text-center">
            <div className="text-sm text-gray-500 bg-gray-50 p-3 rounded-lg">
              <div className="font-medium text-gray-700 mb-1">Standard-Anmeldedaten:</div>
              <div>Benutzername: <span className="font-mono bg-gray-200 px-1 rounded">admin</span></div>
              <div>Passwort: <span className="font-mono bg-gray-200 px-1 rounded">admin123</span></div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default Login;
