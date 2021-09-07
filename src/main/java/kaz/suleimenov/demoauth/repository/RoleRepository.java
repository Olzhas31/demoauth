package kaz.suleimenov.demoauth.repository;

import kaz.suleimenov.demoauth.model.ERole;
import kaz.suleimenov.demoauth.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(ERole name);

}
