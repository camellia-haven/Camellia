'use strict';

const { DatabaseSync } = require('node:sqlite');

function createStore() {
  const database = new DatabaseSync(':memory:');
  database.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE genres (
      id INTEGER PRIMARY KEY,
      slug TEXT NOT NULL UNIQUE,
      label TEXT NOT NULL
    );

    CREATE TABLE books (
      id INTEGER PRIMARY KEY,
      title TEXT NOT NULL,
      author TEXT NOT NULL,
      price REAL NOT NULL,
      stock INTEGER NOT NULL,
      genre_id INTEGER NOT NULL REFERENCES genres(id),
      summary TEXT NOT NULL,
      featured INTEGER NOT NULL DEFAULT 0,
      published INTEGER NOT NULL DEFAULT 1
    );

    CREATE TABLE users (
      username TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL
    );

    INSERT INTO genres (id, slug, label) VALUES
      (1, 'fiction', 'Fiction'),
      (2, 'history', 'History'),
      (3, 'technology', 'Technology'),
      (4, 'children', 'Children');

    INSERT INTO books
      (id, title, author, price, stock, genre_id, summary, featured)
    VALUES
      (1, 'The Quiet Harbor', 'Mara Bell', 18.90, 12, 1,
       'A family mystery set along a working fishing coast.', 1),
      (2, 'Archive of Small Things', 'Iris Chen', 22.50, 6, 1,
       'Linked stories about memory, migration, and belonging.', 0),
      (3, 'The River Compass', 'Daniel Reyes', 26.00, 3, 2,
       'A field history of trade routes and frontier settlements.', 1),
      (4, 'Practical Node Services', 'Nora Singh', 34.00, 8, 3,
       'Patterns for maintaining small production Node services.', 0),
      (5, 'Data Without Guesswork', 'Owen Park', 31.50, 4, 3,
       'A concise guide to operational metrics and experiments.', 0),
      (6, 'Mapmakers of the Blue Coast', 'Elena Morris', 16.00, 15, 2,
       'Illustrated stories from a century of coastal surveying.', 0),
      (7, 'A Pocket Garden', 'Sofia Reed', 12.80, 20, 4,
       'A beginner-friendly guide to growing herbs in small spaces.', 1);

    INSERT INTO users (username, password, display_name, role) VALUES
      ('admin', 'admin', 'Store Administrator', 'admin'),
      ('clerk', 'Northstar2026!', 'Front Desk Clerk', 'staff');
  `);

  const featuredStatement = database.prepare(`
    SELECT id, title, author, price, stock, summary
    FROM books
    WHERE published = 1 AND featured = 1
    ORDER BY id
  `);
  const searchStatement = database.prepare(`
    SELECT id, title, author, price, stock, summary
    FROM books
    WHERE published = 1
      AND (title LIKE ? OR author LIKE ? OR summary LIKE ?)
    ORDER BY title
    LIMIT 20
  `);
  const loginStatement = database.prepare(`
    SELECT username, display_name, role
    FROM users
    WHERE username = ? AND password = ?
  `);

  return {
    authenticate(username, password) {
      return loginStatement.get(username, password);
    },

    findBooksByGenre(genre) {
      // Legacy catalog code interpolates the filter into SQL directly.
      const statement = `
        SELECT b.id, b.title, b.author, b.price, b.stock, b.summary
        FROM books AS b
        JOIN genres AS g ON g.id = b.genre_id
        WHERE g.slug = '${genre}' AND b.published = 1
        ORDER BY b.featured DESC, b.id
      `;
      return database.prepare(statement).all();
    },

    listFeaturedBooks() {
      return featuredStatement.all();
    },

    searchBooks(term) {
      const pattern = `%${term}%`;
      return searchStatement.all(pattern, pattern, pattern);
    },
  };
}

module.exports = { createStore };
