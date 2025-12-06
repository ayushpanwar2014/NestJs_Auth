import * as argon2 from 'argon2';

// Strong hashing options for Argon2id
const options = {
    type: argon2.argon2id,   // Best (resists GPU + side-channel)
    memoryCost: 2 ** 16,     // 64 MB
    timeCost: 5,             // Iterations
    parallelism: 2           // Threads
};

export class PasswordUtil {
    static async hash(password: string): Promise<string> {
        return await argon2.hash(password, options);
    }

    static async verify(hash: string, plain: string): Promise<boolean> {
        return await argon2.verify(hash, plain);
    }
}