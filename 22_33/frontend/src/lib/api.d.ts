export interface User {
  name: string;
  publicKey: string;
  trusted: boolean;
}
export interface UserKeys extends User {
  privateKey: string;
}
export interface SignedMessage {
  nonce?: string;
  senderId: string;
  receiverId: string;
  message: string;
  signature: string;
  timestamp?: string;
}
export interface SendMessage {
  sender: string;
  recipient: string;
  content: string;
}
export interface Api {
  lab(path?: string, body?: unknown, method?: string): Promise<unknown>;
  listUsers(): Promise<User[]>;
  getUser(name: string): Promise<User>;
  getUserKeys(name: string): Promise<UserKeys>;
  createUser(body: { name: string; trusted?: boolean }): Promise<UserKeys>;
  getInbox(name: string): Promise<SignedMessage[]>;
  sign(body: SendMessage): Promise<SignedMessage>;
  send(
    body: SendMessage,
  ): Promise<{ message: SignedMessage; delivered: boolean }>;
  receive(name: string, body: SignedMessage): Promise<{ accepted: boolean }>;
}
export class ApiError extends Error {
  status: number;
  problem?: { detail?: string; errors?: Record<string, string> };
  constructor(message: string, status: number, problem?: unknown);
}
export function createApi(baseUrl?: string, fetchImpl?: typeof fetch): Api;
export function reconcileConversation(
  previous: SignedMessage[],
  incoming: SignedMessage[],
): SignedMessage[];
