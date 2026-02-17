import React, { useState, useEffect } from 'react';
import { SESSION_TIMEOUT } from '../../api';
import { toast } from 'sonner';

const SessionTimer = ({ onLogout }) => {
  const SESSION_DURATION = Math.round(SESSION_TIMEOUT / 1000); // Convert to seconds
  const [timeLeft, setTimeLeft] = useState(SESSION_DURATION);
  const [lastActivity, setLastActivity] = useState(Date.now());

  useEffect(() => {
    const updateActivity = () => {
      setLastActivity(Date.now());
      setTimeLeft(SESSION_DURATION); // Reset timer on activity
      // Also update localStorage for cross-component sync
      localStorage.setItem('lastActivity', Date.now().toString());
    };

    // Activity events to monitor
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    
    events.forEach(event => {
      document.addEventListener(event, updateActivity, true);
    });

    // Timer countdown
    const timer = setInterval(() => {
      setTimeLeft(prev => {
        if (prev <= 1) {
          // Auto logout
          toast.error('Session abgelaufen. Sie werden automatisch abgemeldet.');
          setTimeout(() => {
            onLogout();
          }, 3000);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    // Warning at 5 minutes left
    const warningTimer = setInterval(() => {
      const current = Date.now();
      const timeSinceActivity = (current - lastActivity) / 1000;
      
      if (timeSinceActivity >= 25 * 60 && timeSinceActivity < 25 * 60 + 5) { // 25 minutes
        toast.warning('Session läuft in 5 Minuten ab. Bewegen Sie die Maus, um die Session zu verlängern.');
      }
    }, 5000);

    return () => {
      events.forEach(event => {
        document.removeEventListener(event, updateActivity, true);
      });
      clearInterval(timer);
      clearInterval(warningTimer);
    };
  }, [lastActivity, onLogout, SESSION_DURATION]);

  const formatTime = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  };

  return (
    <div className={`text-sm px-3 py-1 rounded ${timeLeft < 5 * 60 ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-600'}`}>
      Session: {formatTime(timeLeft)}
    </div>
  );
};

export default SessionTimer;
