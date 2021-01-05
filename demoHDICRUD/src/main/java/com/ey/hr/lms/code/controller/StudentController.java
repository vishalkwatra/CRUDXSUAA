package com.ey.hr.lms.code.controller;

import java.sql.SQLException;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ey.hr.lms.code.businesslogic.StudentOperation;
import com.ey.hr.lms.code.entities.Student;

@RestController
public class StudentController {
	
	@Autowired
	StudentOperation studentRepoObj;
	
	@RequestMapping("/students")
	public List<Student> getAllStudent() throws SQLException {
		return studentRepoObj.giveAllStudent();
	}
	
	@RequestMapping("/students/{id}")
	public Student giveStudent(@PathVariable int id) throws SQLException {
		return studentRepoObj.giveStudent(id);
	}

}
