import { z } from "zod";
import { hash, compare } from "bcrypt";
import mysql from "mysql2/promise";
import { randomBytes, createHash } from "node:crypto";
import { Buffer } from "node:buffer";

const loginSchema = z.object({
  email: z.string().trim().toLowerCase().pipe(z.email()),
  password: z.string().min(1).max(72),
});

const registerSchema = z.object({
  email: z.string().trim().toLowerCase().pipe(z.email("Incorrect email")),
  username: z
    .string()
    .min(6, "Username too short")
    .max(32, "Username too long"),
  password: z
    .string()
    .min(8, "Password too short")
    .refine((p) => Buffer.byteLength(p, "utf8") <= 72, "Password is too long"),
});

const tokenSchema = z.object({
  token: z.hex().length(64),
});

const dummy_pass = await hash("dummy_password", 10);

export class Auth {
  constructor(private db: mysql.Pool) {}

  private async CreateToken(user_id: number) {
    await this.db.query(
      "DELETE FROM sessions WHERE user_id = ? AND valid_until < NOW()",
      [user_id],
    );
    const token = randomBytes(32).toString("hex");
    const tokenHash = createHash("sha256").update(token).digest("hex");
    const validUntil = new Date();
    validUntil.setDate(validUntil.getDate() + 1);
    await this.db.query(
      "INSERT INTO sessions (user_id, token, valid_until) VALUES (?,?,?)",
      [user_id, tokenHash, validUntil],
    );
    return token;
  }

  private async RemoveToken(token: string) {
    const tokenHash = createHash("sha256").update(token).digest("hex");
    await this.db.query("DELETE FROM sessions WHERE token = ?", [tokenHash]);
  }

  async Login(body: z.infer<typeof loginSchema>) {
    const result = loginSchema.safeParse(body);
    if (!result.success) {
      return {
        success: false,
        message: "Incorrect email or password format",
      };
    }
    const { email, password } = result.data;

    const [rows] = await this.db.query<mysql.RowDataPacket[]>(
      "SELECT id, password_hash FROM users WHERE email = ?",
      [email],
    );

    if (rows.length === 0) {
      await compare(password, dummy_pass);
      return { success: false, message: "Incorrect email or password" };
    }

    if (await compare(password, rows[0]!.password_hash)) {
      return {
        success: true,
        token: await this.CreateToken(rows[0]!.id),
      };
    }

    return { success: false, message: "Incorrect email or password" };
  }

  async Register(body: z.infer<typeof registerSchema>) {
    const result = registerSchema.safeParse(body);
    if (!result.success) {
      return {
        success: false,
        message: `Incorrect data: ${result.error.issues[0]?.message}`,
      };
    }
    const { email, username, password } = result.data;

    const [hasEmail] = await this.db.query<mysql.RowDataPacket[]>(
      "SELECT id FROM users WHERE email = ?",
      [email],
    );

    if (hasEmail.length !== 0) {
      return {
        success: false,
        message: "This email is already used",
      };
    }

    const password_hash = await hash(password, 10);

    let insert: mysql.ResultSetHeader;
    try {
      [insert] = await this.db.query<mysql.ResultSetHeader>(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        [username, email, password_hash],
      );
    } catch (error: any) {
      if (error.code === "ER_DUP_ENTRY")
        return { success: false, message: "This email is already used" };
      throw error;
    }

    return {
      success: true,
      token: await this.CreateToken(insert.insertId),
    };
  }

  async Logout(body: z.infer<typeof tokenSchema>) {
    const result = tokenSchema.safeParse(body);
    if (!result.success) {
      return {
        success: false,
        message: "Invalid token",
      };
    }
    const { token } = result.data;

    await this.RemoveToken(token);

    return {
      success: true,
    };
  }

  async Authenticate(body: z.infer<typeof tokenSchema>) {
    const result = tokenSchema.safeParse(body);
    if (!result.success) {
      return {
        success: false,
        message: "Invalid token",
      };
    }
    const { token } = result.data;

    const tokenHash = createHash("sha256").update(token).digest("hex");

    const [session] = await this.db.query<mysql.RowDataPacket[]>(
      "SELECT valid_until, user_id FROM sessions WHERE token = ?",
      [tokenHash],
    );

    if (session.length === 0) {
      return {
        success: false,
        message: "Invalid token",
      };
    }

    if (session[0]!.valid_until < new Date()) {
      await this.RemoveToken(token);
      return {
        success: false,
        message: "Invalid token",
      };
    }

    return {
      success: true,
      userId: session[0]!.user_id,
    };
  }
}
