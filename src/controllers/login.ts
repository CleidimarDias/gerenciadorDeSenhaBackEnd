import e, { RequestHandler } from "express";
import z from "zod";
import * as user from "../services/usuario";
import JWT from "jsonwebtoken";

export const login: RequestHandler = async (req, res) => {
  const cpfRegexComFormatacao = /^\d{3}\.\d{3}\.\d{3}-\d{2}$/;
  const removerPontosTracosRegex = /[.-]/g;
  const loginSchema = z.object({
    // cpf: z.string().min(1).max(255),
    cpf: z
      .string()
      .regex(cpfRegexComFormatacao, {
        message: "CPF inválido (formato esperado: XXX.XXX.XXX-XX)",
      })
      .transform((valor) => valor.replace(removerPontosTracosRegex, "")),
    password: z.string().min(6).max(255),
  });

  const body = loginSchema.safeParse(req.body);

  if (!body.success) {
    res.status(400).json({ error: body.error.format() });
    return;
  }

  const UserLogin = await user.getUserByCpfAndPassword({
    ...body.data,
  });

  if (!UserLogin) {
    res.status(500).json({ error: "Usuário ou senha incorretos" });
    return;
  }

  const key = process.env.JWT_SECRET_KEY;

  const token = JWT.sign(
    {
      id: UserLogin.id,
      cpf: UserLogin.cpf,
      name: UserLogin.name,
      role: UserLogin.role,
    },
    key as string,
    { expiresIn: "8h" }
  );

  if (!token) {
    res.status(500).json({ error: "Erro ao gerar token" });
    return;
  }

  res.status(200).json({ token, UserLogin });
  return;
};
