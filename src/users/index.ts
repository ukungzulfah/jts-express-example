// Simulated user database
// In production, replace with real database queries

export interface User {
  id: string;
  email: string;
  password: string; // In production, use hashed passwords!
  name: string;
  permissions: string[];
}

const users: User[] = [
  {
    id: 'user-001',
    email: 'admin@example.com',
    password: 'admin123', // Demo only! Use bcrypt in production
    name: 'Admin User',
    permissions: ['read:profile', 'write:profile', 'admin:access'],
  },
  {
    id: 'user-002',
    email: 'user@example.com',
    password: 'user123', // Demo only! Use bcrypt in production
    name: 'Regular User',
    permissions: ['read:profile'],
  },
];

export function findUserByEmail(email: string): User | undefined {
  return users.find((u) => u.email === email);
}

export function findUserById(id: string): User | undefined {
  return users.find((u) => u.id === id);
}

export function validatePassword(user: User, password: string): boolean {
  // In production, use bcrypt.compare()
  return user.password === password;
}
