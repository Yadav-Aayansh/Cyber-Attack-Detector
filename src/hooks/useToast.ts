import { useState, useRef, useCallback } from 'react';
import { Toast } from '../types';

export function useToast() {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const timeoutsRef = useRef<Map<number, ReturnType<typeof setTimeout>>>(new Map());
  const idCounterRef = useRef(0);

  const generateId = () => Date.now() + idCounterRef.current++;

  const removeToast = useCallback((id: number) => {
    const timeoutId = timeoutsRef.current.get(id);
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutsRef.current.delete(id);
    }
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  const addToast = useCallback((message: string, type: Toast['type'] = 'info') => {
    const id = generateId();
    const newToast: Toast = { id, message, type };

    setToasts(prev => [...prev, newToast]);

    const timeoutId = setTimeout(() => {
      removeToast(id);
    }, 1000);

    timeoutsRef.current.set(id, timeoutId);

    return id;
  }, [removeToast]);

  const clearAllToasts = useCallback(() => {
    timeoutsRef.current.forEach(timeoutId => clearTimeout(timeoutId));
    timeoutsRef.current.clear();
    setToasts([]);
    idCounterRef.current = 0;
  }, []);

  return {
    toasts,
    addToast,
    removeToast,
    clearAllToasts,
  };
}
