package com.tienda.productos;

import java.util.List;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class ProductRepository {

    private final JdbcTemplate jdbc;
    private final ProductRowMapper mapper = new ProductRowMapper();

    public ProductRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Product> findPage(int page, int size) {
        return jdbc.query("SELECT * FROM products ORDER BY id LIMIT ? OFFSET ?", mapper, size, page * size);
    }

    public List<Product> searchByName(String name, String sort) {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + name + "%' ORDER BY " + sort;
        return jdbc.query(sql, mapper);
    }

    public Product save(Product product) {
        jdbc.update("INSERT INTO products (name, price, stock) VALUES (?, ?, ?)",
                product.getName(), product.getPrice(), product.getStock());
        return product;
    }

    public void deleteById(Long id) {
        jdbc.update("DELETE FROM products WHERE id = ?", id);
    }
}
