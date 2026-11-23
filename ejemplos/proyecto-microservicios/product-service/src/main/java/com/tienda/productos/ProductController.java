package com.tienda.productos;

import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    private static final Logger log = LoggerFactory.getLogger(ProductController.class);
    private final ProductRepository repository;

    public ProductController(ProductRepository repository) {
        this.repository = repository;
    }

    @GetMapping
    public List<ProductDto> list(@RequestParam(defaultValue = "0") int page,
                                 @RequestParam(defaultValue = "20") int size) {
        int safeSize = Math.min(size, 100);
        return repository.findPage(page, safeSize).stream().map(ProductDto::from).toList();
    }

    @GetMapping("/search")
    public List<ProductDto> search(@RequestParam String name, @RequestParam(defaultValue = "name") String sort) {
        log.info("search products name={}", name);
        return repository.searchByName(name, sort).stream().map(ProductDto::from).toList();
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping
    public ResponseEntity<ProductDto> create(@RequestBody ProductRequest request) {
        Product saved = repository.save(request.toEntity());
        return ResponseEntity.ok(ProductDto.from(saved));
    }

    @DeleteMapping("/admin/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        repository.deleteById(id);
        log.warn("product {} deleted", id);
        return ResponseEntity.noContent().build();
    }
}
