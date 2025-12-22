declare module 'wappalyzer' {
    export default class Wappalyzer {
        constructor(options?: any);
        open(url: string): Promise<any>;
        destroy(): Promise<void>;
    }
}
