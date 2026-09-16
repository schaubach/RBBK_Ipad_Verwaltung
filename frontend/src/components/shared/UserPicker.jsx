import React from 'react';
import { Input } from '../ui/input';

/**
 * Search + clickable list of users, shared by the "assign pool iPad(s) to
 * user" and "batch-assign per file" admin dialogs. Selection highlighting
 * (selectedUserId) is optional - the assign-to-user dialog acts immediately
 * on click instead of tracking a selection.
 */
export const UserPicker = ({
  users,
  searchQuery,
  onSearchChange,
  onSelectUser,
  selectedUserId = null,
  searchTestId,
  rowTestIdPrefix,
}) => {
  const filteredUsers = users.filter(
    (u) => !searchQuery || u.username.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-2">
      <Input
        placeholder="Benutzer suchen..."
        value={searchQuery}
        onChange={(e) => onSearchChange(e.target.value)}
        data-testid={searchTestId}
      />
      <div className="max-h-64 overflow-y-auto border rounded-lg">
        {filteredUsers.map((u) => (
          <button
            key={u.id}
            onClick={() => onSelectUser(u)}
            className={`w-full text-left p-3 hover:bg-gray-100 border-b last:border-b-0 ${
              selectedUserId === u.id ? 'bg-blue-50' : ''
            }`}
            data-testid={`${rowTestIdPrefix}-${u.id}`}
          >
            <div className="font-medium">{u.username}</div>
            <div className="text-xs text-gray-500">{u.role}</div>
          </button>
        ))}
        {filteredUsers.length === 0 && (
          <div className="p-4 text-center text-sm text-gray-500">Keine Benutzer gefunden</div>
        )}
      </div>
    </div>
  );
};
