import { EntitiesWithCount, EntityMessages, EnumInfo, MetaClassInfo, PermissionInfo, SerializedEntity, UserInfo, View } from "./model";
import { EntityFilter } from "./filter";
export * from './model';
export * from './storage';
export * from './filter';
/**
 * Initializes app.
 * @param {AppConfig} config
 * @returns {CubaApp}
 */
export declare function initializeApp(config?: AppConfig): CubaApp;
/**
 * Retrieve previously initialized app by name.
 * @param {string} appName
 * @returns {CubaApp | null}
 */
export declare function getApp(appName?: string): CubaApp | null;
export declare function removeApp(appName?: string): void;
export interface AppConfig {
    apiUrl?: string;
    name?: string;
    restClientId?: string;
    restClientSecret?: string;
    defaultLocale?: string;
    storage?: Storage;
}
export interface ResponseError extends Error {
    response?: any;
}
export declare type ContentType = "text" | "json" | "blob" | "raw";
export interface FetchOptions extends RequestInit {
    handleAs?: ContentType;
}
export interface EntitiesLoadOptions {
    view?: string;
    sort?: string;
    limit?: number;
    offset?: number;
}
export interface LoginOptions {
    tokenEndpoint: string;
}
export declare class CubaApp {
    name: string;
    apiUrl: string;
    restClientId: string;
    restClientSecret: string;
    defaultLocale: string;
    private storage;
    private static REST_TOKEN_STORAGE_KEY;
    private static USER_NAME_STORAGE_KEY;
    private static LOCALE_STORAGE_KEY;
    messagesCache: EntityMessages;
    enumsCache: EnumInfo[];
    private tokenExpiryListeners;
    private messagesLoadingListeners;
    private enumsLoadingListeners;
    private localeChangeListeners;
    constructor(name?: string, apiUrl?: string, restClientId?: string, restClientSecret?: string, defaultLocale?: string, storage?: Storage);
    restApiToken: string;
    locale: string;
    /**
     * Logs in user and stores token in provided storage.
     * @param {string} login
     * @param {string} password
     * @param {LoginOptions} options You can use custom endpoints e.g. {tokenEndpoint:'ldap/token'}.
     * @returns {Promise<{access_token: string}>}
     */
    login(login: string, password: string, options?: LoginOptions): Promise<{
        access_token: string;
    }>;
    logout(): Promise<any>;
    revokeToken(token: string): Promise<any>;
    loadEntities<T>(entityName: string, options?: EntitiesLoadOptions, fetchOptions?: FetchOptions): Promise<Array<SerializedEntity<T>>>;
    loadEntitiesWithCount<T>(entityName: string, options?: EntitiesLoadOptions, fetchOptions?: FetchOptions): Promise<EntitiesWithCount<T>>;
    searchEntities<T>(entityName: string, entityFilter: EntityFilter, options?: EntitiesLoadOptions, fetchOptions?: FetchOptions): Promise<Array<SerializedEntity<T>>>;
    loadEntity<T>(entityName: string, id: any, options?: {
        view?: string;
    }, fetchOptions?: FetchOptions): Promise<SerializedEntity<T>>;
    deleteEntity(entityName: string, id: any, fetchOptions?: FetchOptions): Promise<void>;
    commitEntity<T extends {
        id?: string;
    }>(entityName: string, entity: T, fetchOptions?: FetchOptions): Promise<Partial<T>>;
    invokeService<T>(serviceName: string, methodName: string, params: any, fetchOptions?: FetchOptions): Promise<T>;
    query<T>(entityName: string, queryName: string, params?: any, fetchOptions?: FetchOptions): Promise<Array<SerializedEntity<T>>>;
    queryWithCount<T>(entityName: string, queryName: string, params?: any, fetchOptions?: FetchOptions): Promise<EntitiesWithCount<T>>;
    queryCount(entityName: string, queryName: string, params?: any, fetchOptions?: FetchOptions): Promise<number>;
    loadMetadata(fetchOptions?: FetchOptions): Promise<MetaClassInfo[]>;
    loadEntityMetadata(entityName: string, fetchOptions?: FetchOptions): Promise<MetaClassInfo>;
    loadEntityViews(entityName: string, fetchOptions?: FetchOptions): Promise<View[]>;
    loadEntityView(entityName: string, viewName: string, fetchOptions?: FetchOptions): Promise<View>;
    loadEntitiesMessages(fetchOptions?: FetchOptions): Promise<EntityMessages>;
    loadEnums(fetchOptions?: FetchOptions): Promise<EnumInfo[]>;
    getPermissions(fetchOptions?: FetchOptions): Promise<PermissionInfo[]>;
    getUserInfo(fetchOptions?: FetchOptions): Promise<UserInfo>;
    fetch<T>(method: string, path: string, data?: any, fetchOptions?: FetchOptions): Promise<T>;
    onLocaleChange(c: any): () => ((locale: string) => {})[];
    onTokenExpiry(c: any): () => (() => {})[];
    onEnumsLoaded(c: any): () => ((enums: any[]) => {})[];
    onMessagesLoaded(c: any): () => ((messages: EntityMessages) => {})[];
    cleanup(): void;
    private isTokenExpiredResponse;
    private _getBasicAuthHeaders;
    private checkStatus;
    private clearAuthData;
}
export declare function getBasicAuthHeaders(client: string, secret: string, locale?: string): {
    [header: string]: string;
};
