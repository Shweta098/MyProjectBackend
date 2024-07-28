package com.app.repositories;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import com.app.pojo.Notice;


@Repository
public interface NoticeRepository extends JpaRepository<Notice, Long> {
	
	@Query(value = "from Notice n where CAST(now() AS TIMESTAMP) BETWEEN noticBegDt AND noticEndDt")
	List<Notice> findAllActiveNotices();

}
