const { hash, compare } = require("bcryptjs");
const AppError = require("../utils/AppError");
const sqliteConnection = require("../database/sqlite");

class UsersController {
  async create(request, response) {
    const { name, email, password } = request.body;
    const database = await sqliteConnection();

    const checkIfUserExists = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    );
    if (checkIfUserExists) {
      throw new AppError("Email já cadastrado.");
    }

    const hashedPassword = await hash(password, 8);

    await database.run(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, hashedPassword]
    );

    return response.status(201).json();
  }

  async update(request, response) {
    const { name, email, password, current_password } = request.body;
    const { id } = request.params;

    const database = await sqliteConnection();
    const user = await database.get("SELECT * FROM users WHERE id = (?)", [id]);
    if (!user) {
      throw new AppError("Usuário não existe.");
    }

    const userWithUpdatedEmail = await database.get(
      "SELECT * FROM users WHERE email = (?)",
      [email]
    );
    if (userWithUpdatedEmail && userWithUpdatedEmail.id !== user.id) {
      throw new AppError("Este e-mail já está em uso.");
    }

    if (password && !current_password) {
      throw new AppError("Informe a senha atual.");
    }

    if (password && current_password) {
      const checkCurentPassword = await compare(
        current_password,
        user.password
      );

      if (!checkCurentPassword) {
        throw new AppError("Senha atual não confere.");
      }

      user.password = await hash(password, 8);
    }

    user.name = name ?? user.name;
    user.email = email ?? user.email;

    await database.run(
      `
    UPDATE users SET
    name = ?,
    email = ?,
    password = ?,
    updated_at = DATETIME('now')
    WHERE id = ?`,
      [user.name, user.email, user.password, id]
    );

    return response.json();
  }
}

module.exports = UsersController;
