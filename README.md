# API backend NodeMovies

Neste projeto foi criada uma API para o projeto NodeMovies.
Utilizando as tecnologias:
Node, Express, Bcryptjs, Knex, SQLite 3.
Ferramentas: beekeeper, Insomnia.

## Documentação

Para instalar os pacotes da pasta node_modules, rodar o seguinte comando:

    npm install

Então, podar o seguinte comando para iniciar o projeto e o banco de dados:

    npm run dev

Por fim, para criar o restante das tabelas pelo knex:

    npm run migrate

O arquivo database.db vai aparecer, contendo as tabelas e suas respectivas relações.

## Tópicos abordados

- Express
- Rotas e métodos HTTP
- Middlewares
- Tratamento de exessões
- Comandos DDL
- Comandos DML
- Migrations
- SQL / SQL Query Builder ( Knex )
- SQLite3
- CRUD.

## Funcionalidades

- Users: Cadastrar, Alterar, Mostrar, Deletar.
- Notes: Cadastrar, Deletar, Mostrar, Pesquisar.
- Tags: Mostrar.
