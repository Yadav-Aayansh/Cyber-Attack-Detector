import { useState, useCallback } from 'react';
import { Toast } from '../types';

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [timeouts, setTimeouts] = useState<Map<number, NodeJS.Timeout>>(new Map());

  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = Date.now();
    const newToast: Toast = { id, message, type };
    
    setToasts(prev => [...prev, newToast]);
    
    // Auto-remove toast after 5 seconds
    const timeoutId = setTimeout(() => {
      setToasts(prev => prev.filter(toast => toast.id !== id));
      setTimeouts(prev => {
        const newTimeouts = new Map(prev);
        newTimeouts.delete(id);
        return newTimeouts;
      });
    }, 5000);
    
    setTimeouts(prev => new Map(prev).set(id, timeoutId));
    
    return id;
  }, []);

  const removeToast = useCallback((id: number) => {
    // Clear the timeout if it exists
    setTimeouts(prev => {
      const timeoutId = prev.get(id);
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      const newTimeouts = new Map(prev);
      newTimeouts.delete(id);
      return newTimeouts;
    });
    
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  const clearAllToasts = useCallback(() => {
    // Clear all timeouts
    setTimeouts(prev => {
      prev.forEach(timeoutId => clearTimeout(timeoutId));
      return new Map();
    });
    
    setToasts([]);
  }, []);

  return {
    toasts,
    addToast,
    removeToast,
    clearAllToasts,
  };
}