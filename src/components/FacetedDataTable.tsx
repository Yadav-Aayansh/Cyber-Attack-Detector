import React, { useState, useMemo } from 'react';
import { ChevronUp, ChevronDown, Search, Filter, X } from 'lucide-react';
import { ProcessedLogEntry, Filters } from '../types';

interface FacetedDataTableProps {
  data: ProcessedLogEntry[];
  isLoading?: boolean;
  filters: Filters;
  onFiltersChange: (filters: Filters) => void;
}

interface FacetOption {
  value: string;
  count: number;
  selected: boolean;
}

interface Facets {
  attackType: FacetOption[];
  method: FacetOption[];
  status: FacetOption[];
}

export function FacetedDataTable({ data, isLoading, filters, onFiltersChange }: FacetedDataTableProps) {
  const [sortField, setSortField] = useState<keyof ProcessedLogEntry>('timestamp');
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('desc');
  const [currentPage, setCurrentPage] = useState(1);
  const [expandedFacets, setExpandedFacets] = useState<Record<string, boolean>>({
    attackType: true,
    method: true,
    status: true,
  });
  const itemsPerPage = 50;

  // Build facets from data
  const facets: Facets = useMemo(() => {
    const attackTypeCounts: Record<string, number> = {};
    const methodCounts: Record<string, number> = {};
    const statusCounts: Record<string, number> = {};

    data.forEach(entry => {
      attackTypeCounts[entry.attack_type] = (attackTypeCounts[entry.attack_type] || 0) + 1;
      methodCounts[entry.method] = (methodCounts[entry.method] || 0) + 1;
      statusCounts[entry.status.toString()] = (statusCounts[entry.status.toString()] || 0) + 1;
    });

    const selectedAttackTypes = filters.attackType.split(',').filter(Boolean);
    const selectedMethods = filters.method?.split(',').filter(Boolean) || [];
    const selectedStatuses = filters.statusCode.split(',').filter(Boolean);

    return {
      attackType: Object.entries(attackTypeCounts)
        .map(([value, count]) => ({
          value,
          count,
          selected: selectedAttackTypes.includes(value),
        }))
        .sort((a, b) => b.count - a.count),
      method: Object.entries(methodCounts)
        .map(([value, count]) => ({
          value,
          count,
          selected: selectedMethods.includes(value),
        }))
        .sort((a, b) => b.count - a.count),
      status: Object.entries(statusCounts)
        .map(([value, count]) => ({
          value,
          count,
          selected: selectedStatuses.includes(value),
        }))
        .sort((a, b) => b.count - a.count),
    };
  }, [data, filters]);

  const filteredData = useMemo(() => {
    return data.filter(entry => {
      const selectedAttackTypes = filters.attackType.split(',').filter(Boolean);
      const selectedMethods = filters.method?.split(',').filter(Boolean) || [];
      const selectedStatuses = filters.statusCode.split(',').filter(Boolean);

      const matchesAttackType = selectedAttackTypes.length === 0 || selectedAttackTypes.includes(entry.attack_type);
      const matchesMethod = selectedMethods.length === 0 || selectedMethods.includes(entry.method);
      const matchesStatus = selectedStatuses.length === 0 || selectedStatuses.includes(entry.status.toString());
      const matchesIp = !filters.ip || entry.ip.includes(filters.ip);
      const matchesSearch = !filters.search || Object.values(entry).some(value => 
        value.toString().toLowerCase().includes(filters.search.toLowerCase())
      );
      
      return matchesAttackType && matchesMethod && matchesStatus && matchesIp && matchesSearch;
    });
  }, [data, filters]);

  const sortedData = useMemo(() => {
    return [...filteredData].sort((a, b) => {
      const aValue = a[sortField];
      const bValue = b[sortField];
      
      if (aValue < bValue) return sortDirection === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortDirection === 'asc' ? 1 : -1;
      return 0;
    });
  }, [filteredData, sortField, sortDirection]);

  const paginatedData = useMemo(() => {
    const startIndex = (currentPage - 1) * itemsPerPage;
    return sortedData.slice(startIndex, startIndex + itemsPerPage);
  }, [sortedData, currentPage, itemsPerPage]);

  const totalPages = Math.ceil(sortedData.length / itemsPerPage);

  const handleSort = (field: keyof ProcessedLogEntry) => {
    if (sortField === field) {
      setSortDirection(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortDirection('asc');
    }
    setCurrentPage(1);
  };

  const handleFacetToggle = (facetType: keyof Facets, value: string) => {
    let newValues: string[] = [];
    
    if (facetType === 'attackType') {
      newValues = filters.attackType.split(',').filter(Boolean);
    } else if (facetType === 'method') {
      newValues = filters.method?.split(',').filter(Boolean) || [];
    } else if (facetType === 'status') {
      newValues = filters.statusCode.split(',').filter(Boolean);
    }

    if (newValues.includes(value)) {
      newValues = newValues.filter(v => v !== value);
    } else {
      newValues.push(value);
    }

    const newFilters = { ...filters };
    if (facetType === 'attackType') {
      newFilters.attackType = newValues.join(',');
    } else if (facetType === 'method') {
      newFilters.method = newValues.join(',');
    } else if (facetType === 'status') {
      newFilters.statusCode = newValues.join(',');
    }

    onFiltersChange(newFilters);
    setCurrentPage(1);
  };

  const clearFacet = (facetType: keyof Facets) => {
    const newFilters = { ...filters };
    if (facetType === 'attackType') {
      newFilters.attackType = '';
    } else if (facetType === 'method') {
      newFilters.method = '';
    } else if (facetType === 'status') {
      newFilters.statusCode = '';
    }
    onFiltersChange(newFilters);
    setCurrentPage(1);
  };

  const toggleFacetExpansion = (facetType: string) => {
    setExpandedFacets(prev => ({
      ...prev,
      [facetType]: !prev[facetType],
    }));
  };

  const getSelectedCount = (facetType: keyof Facets) => {
    return facets[facetType].filter(option => option.selected).length;
  };

  const SortIcon = ({ field }: { field: keyof ProcessedLogEntry }) => {
    if (sortField !== field) return null;
    return sortDirection === 'asc' ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />;
  };

  const FacetSection = ({ title, facetType, options }: { title: string; facetType: keyof Facets; options: FacetOption[] }) => {
    const isExpanded = expandedFacets[facetType];
    const selectedCount = getSelectedCount(facetType);
    const displayOptions = isExpanded ? options : options.slice(0, 5);

    return (
      <div className="border-b border-gray-200 dark:border-gray-700 pb-4">
        <div className="flex items-center justify-between mb-3">
          <button
            onClick={() => toggleFacetExpansion(facetType)}
            className="flex items-center space-x-2 text-sm font-medium text-gray-900 dark:text-white hover:text-blue-600 dark:hover:text-blue-400"
          >
            <span>{title}</span>
            {selectedCount > 0 && (
              <span className="bg-blue-100 dark:bg-blue-900/20 text-blue-800 dark:text-blue-300 px-2 py-0.5 rounded-full text-xs">
                {selectedCount}
              </span>
            )}
            {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>
          {selectedCount > 0 && (
            <button
              onClick={() => clearFacet(facetType)}
              className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
            >
              Clear
            </button>
          )}
        </div>
        
        <div className="space-y-2">
          {displayOptions.map(option => (
            <label key={option.value} className="flex items-center space-x-2 cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700 p-1 rounded">
              <input
                type="checkbox"
                checked={option.selected}
                onChange={() => handleFacetToggle(facetType, option.value)}
                className="w-4 h-4 text-blue-600 border-gray-300 dark:border-gray-600 rounded focus:ring-blue-500 dark:focus:ring-blue-400"
              />
              <span className="text-sm text-gray-700 dark:text-gray-300 flex-1 truncate" title={option.value}>
                {option.value}
              </span>
              <span className="text-xs text-gray-500 dark:text-gray-400 bg-gray-100 dark:bg-gray-600 px-2 py-0.5 rounded-full">
                {option.count}
              </span>
            </label>
          ))}
          
          {!isExpanded && options.length > 5 && (
            <button
              onClick={() => toggleFacetExpansion(facetType)}
              className="text-xs text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 mt-2"
            >
              Show {options.length - 5} more...
            </button>
          )}
        </div>
      </div>
    );
  };

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-xl p-8 text-center">
        <div className="w-8 h-8 border-4 border-blue-500 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
        <p className="text-gray-600 dark:text-gray-300">Analyzing log data...</p>
      </div>
    );
  }

  return (
    <div className="flex gap-6 min-h-0">
      {/* Faceted Filters Sidebar */}
      <div className="w-80 flex-shrink-0">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-gray-200 dark:border-gray-700 p-4 sticky top-4 max-h-[calc(100vh-2rem)] overflow-y-auto sidebar-scrollbar">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white flex items-center">
              <Filter className="w-5 h-5 mr-2" />
              Filters
            </h3>
            <button
              onClick={() => onFiltersChange({ attackType: '', statusCode: '', ip: '', dateRange: '', severity: '', search: '', method: '' })}
              className="text-sm text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300"
            >
              Clear All
            </button>
          </div>

          {/* Search */}
          <div className="mb-6">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={filters.search}
                onChange={(e) => onFiltersChange({ ...filters, search: e.target.value })}
                placeholder="Search all fields..."
                className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
              />
            </div>
          </div>

          {/* IP Filter */}
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
              IP Address
            </label>
            <input
              type="text"
              value={filters.ip}
              onChange={(e) => onFiltersChange({ ...filters, ip: e.target.value })}
              placeholder="Filter by IP..."
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
            />
          </div>

          {/* Facets */}
          <div className="space-y-6">
            <FacetSection title="Attack Type" facetType="attackType" options={facets.attackType} />
            <FacetSection title="HTTP Method" facetType="method" options={facets.method} />
            <FacetSection title="Status Code" facetType="status" options={facets.status} />
          </div>

          {/* Results Summary */}
          <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-700">
            <div className="text-sm text-gray-600 dark:text-gray-300">
              <div className="font-medium mb-1">Results Summary</div>
              <div>Showing {filteredData.length} of {data.length} entries</div>
              {filteredData.length !== data.length && (
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  {data.length - filteredData.length} entries filtered out
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Results Table */}
      <div className="flex-1 min-w-0">
        <div className="bg-white dark:bg-gray-800 rounded-xl shadow-lg overflow-hidden">
          {/* Results Header */}
          <div className="p-4 border-b border-gray-200 dark:border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">
                  Security Threats ({filteredData.length.toLocaleString()})
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-300">
                  Page {currentPage} of {totalPages}
                </p>
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="overflow-x-auto overflow-y-auto max-h-[600px] premium-scrollbar">
            <table className="w-full min-w-[1200px]">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  {[
                    { key: 'ip', label: 'IP Address' },
                    { key: 'timestamp', label: 'Timestamp' },
                    { key: 'method', label: 'Method' },
                    { key: 'path', label: 'Path' },
                    { key: 'status', label: 'Status' },
                    { key: 'attack_type', label: 'Attack Type' },
                    { key: 'suspicion_reason', label: 'Suspicion Reason' },
                  ].map(({ key, label }) => (
                    <th
                      key={key}
                      className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-600"
                      onClick={() => handleSort(key as keyof ProcessedLogEntry)}
                    >
                      <div className="flex items-center space-x-1">
                        <span>{label}</span>
                        <SortIcon field={key as keyof ProcessedLogEntry} />
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {paginatedData.map((entry, index) => (
                  <tr key={index} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-white">
                      {entry.ip}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-300">
                      {new Date(entry.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        entry.method === 'GET' ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300' :
                        entry.method === 'POST' ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-300' :
                        'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                      }`}>
                        {entry.method}
                      </span>
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-900 dark:text-white max-w-xs">
                      <div className="truncate" title={entry.path}>
                      {entry.path}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                        entry.status >= 200 && entry.status < 300 ? 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-300' :
                        entry.status >= 300 && entry.status < 400 ? 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-300' :
                        entry.status >= 400 && entry.status < 500 ? 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-300' :
                        entry.status >= 500 ? 'bg-purple-100 text-purple-800 dark:bg-purple-900/20 dark:text-purple-300' :
                        'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                      }`}>
                        {entry.status}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {entry.attack_type}
                    </td>
                    <td className="px-6 py-4 text-sm text-gray-500 dark:text-gray-300 max-w-xs">
                      <div className="truncate" title={entry.suspicion_reason}>
                      {entry.suspicion_reason}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="px-6 py-3 border-t border-gray-200 dark:border-gray-700 flex items-center justify-between bg-white dark:bg-gray-800">
              <div className="text-sm text-gray-600 dark:text-gray-300">
                Page {currentPage} of {totalPages}
              </div>
              <div className="flex space-x-2">
                <button
                  onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                  disabled={currentPage === 1}
                  className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
                >
                  Previous
                </button>
                <button
                  onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                  disabled={currentPage === totalPages}
                  className="px-3 py-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed hover:bg-gray-50 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}