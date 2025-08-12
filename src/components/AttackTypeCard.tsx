import React from 'react';
import { Eye, Shield, AlertTriangle, Info, Play, CheckCircle, Code } from 'lucide-react';
import { AttackTypeConfig } from '../types';

interface AttackTypeCardProps {
  config: AttackTypeConfig;
  count: number;
  isLoading?: boolean;
  onScan: () => void;
  onViewDetails: () => void;
  onViewFunction?: () => void;
  hasResults?: boolean;
}

const severityIcons = {
  high: AlertTriangle,
  medium: Shield,
  low: Info,
};

export function AttackTypeCard({ config, count, isLoading, onScan, onViewDetails, onViewFunction, hasResults }: AttackTypeCardProps) {
  const SeverityIcon = severityIcons[config.severity];

  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all duration-200 hover:-translate-y-1 border border-gray-200 dark:border-gray-700">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center space-x-3">
          <div 
            className="p-2 rounded-lg"
            style={{ backgroundColor: `${config.color}20` }}
          >
            <SeverityIcon 
              className="w-6 h-6" 
              style={{ color: config.color }}
            />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
              {config.name}
            </h3>
            <span 
              className={`
                inline-block px-2 py-1 rounded-full text-xs font-medium
                ${config.severity === 'high' ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300' : ''}
                ${config.severity === 'medium' ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300' : ''}
                ${config.severity === 'low' ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300' : ''}
              `}
            >
              {config.severity.toUpperCase()}
            </span>
          </div>
        </div>
        <div className="text-right">
          <div className="text-2xl font-bold text-gray-900 dark:text-white">
            {isLoading ? '...' : count.toLocaleString()}
          </div>
          <div className="text-xs text-gray-500 dark:text-gray-400">
            instances
          </div>
        </div>
      </div>

      <p className="text-sm text-gray-600 dark:text-gray-300 mb-4">
        {config.description}
      </p>

      <div className="space-y-2">
        <button
          onClick={onScan}
          disabled={isLoading}
          className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white rounded-lg transition-colors"
        >
          {hasResults ? (
            <>
              <CheckCircle className="w-4 h-4" />
              <span>Rescan</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4" />
              <span>Scan</span>
            </>
          )}
        </button>
        
        {hasResults && (
          <button
            onClick={onViewDetails}
            className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg transition-colors"
          >
            <Eye className="w-4 h-4" />
            <span>View Results ({count})</span>
          </button>
        )}
        
        {onViewFunction && (
          <button
            onClick={onViewFunction}
            className="w-full flex items-center justify-center space-x-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg transition-colors"
          >
            <Code className="w-4 h-4" />
            <span>View Function</span>
          </button>
        )}
      </div>
    </div>
  );
}